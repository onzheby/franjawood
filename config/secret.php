<?php
if (!defined('APP_BOOT')) { http_response_code(404); exit; }
return [
  'SMTP_HOST'        => 'mail.c49.cl',
  'SMTP_USER'        => 'contacto@c49.cl',
  'SMTP_PASS'        => 'c492025..,,',
  // reCAPTCHA
  'RECAPTCHA_SECRET' => '6LfLEcQrAAAAALMWpKj5lD4VkMHC85jZoUPPQpLE', // ← reemplaza
];
