import { Router } from 'express';
import {
  handleKnockoutAssessment,
  handlePremiumCalculation,
  handlePremiumStream,
  handlePremiumIndicate,
  handleSubmissionStatus,
} from '../controllers';
import {
  KnockoutAssessmentRequest,
  KnockoutAssessmentResponse,
  PremiumCalculationRequest,
  PremiumCalculationResponse,
  PremiumStreamRequest,
  PremiumIndicateRequest,
  PremiumIndicateResponse,
  SubmissionStatusResponse,
} from '../types';

const router = Router();

// Knockout Assessment
router.post<{}, KnockoutAssessmentResponse, KnockoutAssessmentRequest>(
  '/knockout-assessment',
  handleKnockoutAssessment
);

// Premium Calculation
router.post<{}, PremiumCalculationResponse, PremiumCalculationRequest>(
  '/premium/calculate',
  handlePremiumCalculation
);

// Premium Stream
router.post<{}, never, PremiumStreamRequest>(
  '/premium/stream',
  handlePremiumStream
);

// Premium Indication
router.post<{}, PremiumIndicateResponse, PremiumIndicateRequest>(
  '/premium/indicate',
  handlePremiumIndicate
);

// Submission Status
router.get<{ submissionId: string }, SubmissionStatusResponse>(
  '/submission/:submissionId/status',
  handleSubmissionStatus
);

export const ratingRoutes = router;
