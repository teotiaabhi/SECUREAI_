// Test: negative for rule XSS-PHP-001
// Expected: should_not_trigger
// Category: xss
// Language: php
<?php

/**
 * Safe PHP form handling with proper output encoding
 * using htmlspecialchars on every user-controlled value.
 */

header("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

function sanitize(string $input): string {
    return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
}

$name    = '';
$email   = '';
$message = '';
$submitted = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name    = trim($_POST['name'] ?? '');
    $email   = trim($_POST['email'] ?? '');
    $message = trim($_POST['message'] ?? '');

    if ($name !== '' && $email !== '' && $message !== '') {
        $submitted = true;
    }
}

$pageTitle = isset($_GET['title']) ? sanitize($_GET['title']) : 'Contact Us';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title><?php echo $pageTitle; ?></title>
</head>
<body>
    <h1><?php echo $pageTitle; ?></h1>

    <?php if ($submitted): ?>
        <div class="success-banner">
            <p>Thank you, <?php echo sanitize($name); ?>!</p>
            <p>We will reply to <?php echo sanitize($email); ?> shortly.</p>
            <blockquote><?php echo sanitize($message); ?></blockquote>
        </div>
    <?php else: ?>
        <form method="POST" action="">
            <label for="name">Name</label>
            <input type="text" id="name" name="name"
                   value="<?php echo sanitize($name); ?>">

            <label for="email">Email</label>
            <input type="email" id="email" name="email"
                   value="<?php echo sanitize($email); ?>">

            <label for="message">Message</label>
            <textarea id="message" name="message"><?php echo sanitize($message); ?></textarea>

            <button type="submit">Send</button>
        </form>
    <?php endif; ?>
</body>
</html>
