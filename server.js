const express = require('express');
const app = express();

app.use(express.json());

// Health check route
app.get('/health', (req, res) => {
  res.send('Integration Server Running ✅');
});

// Temporary endpoint to test webhook
app.post('/webhook/lendingdox', (req, res) => {
  console.log('Received LendingDox payload:', req.body);
  res.send('Received ✅');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
