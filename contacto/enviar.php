<?php
declare(strict_types=1);
session_start();
header('Content-Type: application/json; charset=UTF-8');

define('APP_BOOT', true);
require __DIR__ . '/../vendor/autoload.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

/* ===== Cargar secretos ===== */
$cfg = require __DIR__ . '/../config/secret.php';
$SMTP_HOST        = $cfg['SMTP_HOST']        ?? 'mail.c49.cl';
$SMTP_USER        = $cfg['SMTP_USER']        ?? 'contacto@c49.cl';
$SMTP_PASS        = $cfg['SMTP_PASS']        ?? '';
$RECAPTCHA_SECRET = $cfg['RECAPTCHA_SECRET'] ?? '';

/* ===== Rate limit simple ===== */
$_SESSION['last_submit'] = $_SESSION['last_submit'] ?? 0;
if (time() - (int)$_SESSION['last_submit'] < 20) {
  http_response_code(429);
  echo json_encode(['ok'=>false,'msg'=>'Muy seguido, intenta en unos segundos.']); exit;
}
$_SESSION['last_submit'] = time();

/* ===== Solo POST + Honeypot ===== */
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
  http_response_code(405);
  echo json_encode(['ok'=>false,'msg'=>'Método no permitido']); exit;
}
if (!empty($_POST['_gotcha'] ?? '')) { echo json_encode(['ok'=>true,'msg'=>'Recibido']); exit; }

/* ===== CSRF ===== */
if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['_csrf'] ?? '')) {
  http_response_code(403);
  echo json_encode(['ok'=>false,'msg'=>'Sesión inválida, recarga la página.']); exit;
}
unset($_SESSION['csrf']); // un solo uso

/* ===== reCAPTCHA (v2 checkbox) ===== */
$captchaResp = trim($_POST['g-recaptcha-response'] ?? '');
if ($captchaResp === '' || $RECAPTCHA_SECRET === '') {
  http_response_code(422);
  echo json_encode(['ok'=>false,'msg'=>'Verificación anti-bot requerida.']); exit;
}
$ch = curl_init('https://www.google.com/recaptcha/api/siteverify');
curl_setopt_array($ch, [
  CURLOPT_POST => true,
  CURLOPT_POSTFIELDS => http_build_query([
    'secret'   => $RECAPTCHA_SECRET,
    'response' => $captchaResp,
    'remoteip' => $_SERVER['REMOTE_ADDR'] ?? null,
  ]),
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_TIMEOUT => 10,
]);
$verify = curl_exec($ch);
if ($verify === false) {
  curl_close($ch);
  http_response_code(502);
  echo json_encode(['ok'=>false,'msg'=>'Error de verificación (captcha).']); exit;
}
curl_close($ch);
$cap = json_decode($verify, true);
if (!($cap['success'] ?? false)) {
  http_response_code(422);
  echo json_encode(['ok'=>false,'msg'=>'No pudimos verificar que seas humano.']); exit;
}

/* ===== Datos ===== */
$soloLinea = fn($s)=>trim(preg_replace("/[\r\n]+/", ' ', (string)$s));
$safe      = fn($v)=>nl2br(htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'));

$nombre   = $soloLinea($_POST['nombre']   ?? '');
$empresa  = $soloLinea($_POST['empresa']  ?? '');
$telefono = $soloLinea($_POST['telefono'] ?? '');
$email    = $soloLinea($_POST['email']    ?? '');
$mensaje  = trim($_POST['mensaje'] ?? '');
$subject  = $soloLinea($_POST['_subject'] ?? 'Nueva solicitud');

if ($nombre === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
  http_response_code(422);
  echo json_encode(['ok'=>false,'msg'=>'Nombre y email válidos son obligatorios.']); exit;
}
if ($telefono !== '' && !preg_match('/^[0-9 +()\-]{6,20}$/', $telefono)) {
  http_response_code(422);
  echo json_encode(['ok'=>false,'msg'=>'Teléfono inválido.']); exit;
}

/* ===== Envío con PHPMailer (c49.cl) ===== */
$mail = new PHPMailer(true);

try {
  $mail->isSMTP();
  $mail->Host       = $SMTP_HOST;
  $mail->SMTPAuth   = true;
  $mail->Username   = $SMTP_USER;                 // contacto@c49.cl
  $mail->Password   = $SMTP_PASS;                 // c492025..,,
  $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
  $mail->Port       = 465;                        // SSL/SMTPS
  $mail->CharSet    = 'UTF-8';
  $mail->Timeout    = 15;
  $mail->Sender     = $SMTP_USER;                 // Return-Path

  // Seguridad TLS (cert válido en cPanel)
  $mail->SMTPOptions = [
    'ssl' => [
      'verify_peer'       => true,
      'verify_peer_name'  => true,
      'allow_self_signed' => false,
    ],
  ];

  /* Remitente y destinatario */
  $mail->setFrom('contacto@c49.cl', 'Clave49 Seguridad');
  $mail->addAddress('contacto@c49.cl', 'Contacto C49');
  // (Opcional) Copia oculta de respaldo:
  // $mail->addBCC('tu_correo_de_respaldo@ejemplo.cl');

  // Responder al correo del visitante
  if ($email !== '') {
    $mail->addReplyTo($email, $nombre);
  }

  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

  $mail->Subject = $subject;
  $mail->isHTML(true);
  $mail->Body =
    '<h3>Nueva solicitud desde el sitio</h3>'.
    '<table cellpadding="8" cellspacing="0" border="1" style="border-collapse:collapse;font-family:Arial,Helvetica,sans-serif;font-size:14px">'.
    "<tr><th align='left'>Nombre</th><td>{$safe($nombre)}</td></tr>".
    "<tr><th align='left'>Empresa</th><td>{$safe($empresa)}</td></tr>".
    "<tr><th align='left'>Teléfono</th><td>{$safe($telefono)}</td></tr>".
    "<tr><th align='left'>Email</th><td>{$safe($email)}</td></tr>".
    "<tr><th align='left'>Mensaje</th><td>{$safe($mensaje)}</td></tr>".
    "<tr><th align='left'>Fecha</th><td>".date('Y-m-d H:i:s')."</td></tr>".
    "<tr><th align='left'>IP</th><td>{$safe($ip)}</td></tr>".
    '</table>';
  $mail->AltBody =
    "Nombre: $nombre\r\n".
    "Empresa: $empresa\r\n".
    "Teléfono: $telefono\r\n".
    "Email: $email\r\n".
    "Mensaje:\r\n$mensaje\r\n".
    "Fecha: ".date('Y-m-d H:i:s')."\r\n".
    "IP: $ip";

  $mail->send();

  /* ===== Auto-respuesta al cliente (no interrumpe si falla) ===== */
  if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
    try {
      $ack = new PHPMailer(true);
      $ack->isSMTP();
      $ack->Host       = $SMTP_HOST;
      $ack->SMTPAuth   = true;
      $ack->Username   = $SMTP_USER;
      $ack->Password   = $SMTP_PASS;
      $ack->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
      $ack->Port       = 465;
      $ack->CharSet    = 'UTF-8';
      $ack->Sender     = $SMTP_USER;

      $ack->setFrom('contacto@c49.cl', 'Clave49 Seguridad');
      $ack->addAddress($email, $nombre);
      $ack->addReplyTo('contacto@c49.cl', 'Clave49 Seguridad');

      $ack->Subject = 'Hemos recibido tu mensaje';
      $ack->isHTML(true);
      $ack->Body =
        'Hola '.$safe($nombre).',<br><br>'.
        'Gracias por contactarnos. Hemos recibido tu solicitud y un asesor te escribirá en &lt; 24 horas.<br><br>'.
        '<b>Resumen de tu consulta</b><br>'.
        '<ul style="margin:0;padding-left:18px">'.
        '<li><b>Nombre:</b> '.$safe($nombre).'</li>'.
        '<li><b>Empresa:</b> '.$safe($empresa).'</li>'.
        '<li><b>Teléfono:</b> '.$safe($telefono).'</li>'.
        '<li><b>Email:</b> '.$safe($email).'</li>'.
        '</ul><br>'.
        '<b>Mensaje:</b><br>'.$safe($mensaje).'<br><br>'.
        '— Equipo de Clave49 Seguridad';
      $ack->AltBody =
        "Hola $nombre,\n\n".
        "Gracias por contactarnos. Hemos recibido tu solicitud y te responderemos en < 24 horas.\n\n".
        "Resumen:\n".
        "Nombre: $nombre\nEmpresa: $empresa\nTeléfono: $telefono\nEmail: $email\n\n".
        "Mensaje:\n$mensaje\n\n".
        "— Equipo de Clave49 Seguridad";

      $ack->send();
    } catch (\Throwable $e) {
      @error_log('['.date('c').'] ACK: '.$e->getMessage()."\n", 3, __DIR__.'/mail_errors.log');
    }
  }

  echo json_encode(['ok'=>true,'msg'=>'¡Gracias! Hemos recibido tu solicitud.']);
} catch (Exception $e) {
  @error_log('['.date('c').'] '.$mail->ErrorInfo."\n", 3, __DIR__.'/mail_errors.log');
  http_response_code(500);
  echo json_encode(['ok'=>false,'msg'=>'No se pudo enviar el correo. Inténtalo nuevamente.']);
}
