import { Router } from 'express';
import {
  handleKnockoutAssessment,
  handlePremiumCalculation,
  handlePremiumStream,
  handlePremiumIndicate,
  handleSubmissionStatus,
} from '../controllers';

const router = Router();

// Knockout Assessment
router.post('/knockout-assessment', handleKnockoutAssessment);

// Premium Calculation
router.post('/premium/calculate', handlePremiumCalculation);

// Premium Stream
router.post('/premium/stream', handlePremiumStream);

// Premium Indication
router.post('/premium/indicate', handlePremiumIndicate);

// Submission Status
router.get('/submission/:submissionId/status', handleSubmissionStatus);

export const ratingRoutes = router;
