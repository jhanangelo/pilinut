<?php
session_start();
include('db.php');

if (!isset($_SESSION["admin"])) {
    header("Location: index.php");
    exit();
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $jar_qty = (int)$_POST["jar_qty"];
    $candy_qty = (int)$_POST["candy_qty"];
    $total = ($jar_qty * 350) + ($candy_qty * 50);
    $admin_id = $_SESSION["admin_id"]; // ✅ Set during login

    // ✅ Insert into database
    $stmt = $conn->prepare("INSERT INTO orders (admin_id, jar_qty, candy_qty, total) VALUES (?, ?, ?, ?)");
    $stmt->bind_param("iiid", $admin_id, $jar_qty, $candy_qty, $total);
    $stmt->execute();
}

?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Dashboard - Pili Nuts</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="style.css">
</head>
<body class="dashboard-body">
    <div class="navbar">
        <h2>Pili Nuts Dashboard</h2>
        <a href="logout.php">Logout</a>
    </div>
    <div class="content">
        <div class="card">
            <h3>Place Order</h3>
            <form method="post" class="order-form">
                <label>Jar (₱350):</label>
                <input type="number" name="jar_qty" value="0" min="0">
                <label>Sweet Candy (₱50):</label>
                <input type="number" name="candy_qty" value="0" min="0">
                <button type="submit">Submit Order</button>
            </form>
        </div>

        <div class="card">
            <h3>Order History</h3>
            <pre class="order-history">
<?php
$result = $conn->query("SELECT * FROM orders ORDER BY created_at DESC");

if ($result && $result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        echo htmlspecialchars("{$row['created_at']} | Jars: {$row['jar_qty']} | Candies: {$row['candy_qty']} | Total: ₱{$row['total']}\n");
    }
} else {
    echo "No orders yet.";
}
?>
            </pre>
        </div>
    </div>
</body>
</html>
