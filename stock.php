<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Manage Stocks</title>
  <style>
    body { font-family: Arial; padding: 20px; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ccc; padding: 10px; }
    input[type="number"] { width: 60px; }
    button { padding: 5px 10px; margin-left: 5px; }
  </style>
</head>
<body>
  <h1>Manage Product Stock</h1>

  <table>
    <thead>
      <tr>
        <th>Name</th>
        <th>Description</th>
        <th>Price</th>
        <th>Stock</th>
        <th>Actions</th>
      </tr>
    </thead>
    <tbody id="productTable">
      <!-- Products will be loaded here -->
    </tbody>
  </table>

  <script>
    async function fetchProducts() {
      const res = await fetch('/admin/products');
      const products = await res.json();
      const table = document.getElementById('productTable');
      table.innerHTML = '';

      products.forEach(p => {
        table.innerHTML += `
          <tr>
            <td>${p.name}</td>
            <td>${p.description}</td>
            <td>$${p.price.toFixed(2)}</td>
            <td>
              <input type="number" value="${p.stock_quantity}" min="0" id="stock-${p.product_id}">
            </td>
            <td>
              <button onclick="updateStock(${p.product_id})">Update</button>
              <button onclick="deleteProduct(${p.product_id})">Delete</button>
            </td>
          </tr>`;
      });
    }

    async function updateStock(id) {
      const qty = document.getElementById(`stock-${id}`).value;
      await fetch(`/admin/products/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ stock_quantity: qty })
      });
      alert('Stock updated!');
      fetchProducts();
    }

    async function deleteProduct(id) {
      if (confirm('Are you sure?')) {
        await fetch(`/admin/products/${id}`, { method: 'DELETE' });
        alert('Product removed!');
        fetchProducts();
      }
    }

    fetchProducts();
  </script>
</body>
</html>
