import express from 'express';
import { ratingRoutes } from './services/rating/routes';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Rating Service Routes
app.use('/api', ratingRoutes);

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
