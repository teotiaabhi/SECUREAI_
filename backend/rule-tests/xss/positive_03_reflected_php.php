<?php
/**
 * Test:     positive_03_reflected_php
 * Expected: TRIGGER XSS-PHP-001
 * Category: XSS
 * Language: PHP
 *
 * Description:
 *   PHP page that processes a search form and echoes the $_GET
 *   parameter directly into the HTML response without any
 *   sanitization (no htmlspecialchars). Classic reflected XSS.
 */

$searchQuery = isset($_GET['q']) ? $_GET['q'] : '';
$category = isset($_GET['category']) ? $_GET['category'] : 'all';
$results = [];

if (!empty($searchQuery)) {
    // Simulate database search
    $pdo = new PDO('mysql:host=localhost;dbname=products', 'app_user', 'app_pass');
    $stmt = $pdo->prepare("SELECT * FROM products WHERE name LIKE :query AND category = :cat");
    $stmt->execute([':query' => '%' . $searchQuery . '%', ':cat' => $category]);
    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Product Search</title>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET" action="">
        <input type="text" name="q" value="<?php echo $searchQuery; ?>" placeholder="Search...">
        <select name="category">
            <option value="all">All Categories</option>
            <option value="electronics">Electronics</option>
        </select>
        <button type="submit">Search</button>
    </form>

    <!-- VULNERABLE: Direct echo of user input without htmlspecialchars -->
    <p>Showing results for: <strong><?php echo $searchQuery; ?></strong> in <?php echo $category; ?></p>

    <?php if (count($results) > 0): ?>
        <ul>
        <?php foreach ($results as $row): ?>
            <li><?php echo $row['name']; ?> - $<?php echo $row['price']; ?></li>
        <?php endforeach; ?>
        </ul>
    <?php elseif (!empty($searchQuery)): ?>
        <!-- VULNERABLE: Reflected user input -->
        <p>No results found for "<?php echo $_GET['q']; ?>"</p>
    <?php endif; ?>
</body>
</html>
