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
router.post<
  Record<string, never>,
  KnockoutAssessmentResponse,
  KnockoutAssessmentRequest
>('/knockout-assessment', (req, res) => handleKnockoutAssessment(req, res));

// Premium Calculation
router.post<
  Record<string, never>,
  PremiumCalculationResponse,
  PremiumCalculationRequest
>('/premium/calculate', (req, res) => handlePremiumCalculation(req, res));

// Premium Stream
router.post<
  Record<string, never>,
  never,
  PremiumStreamRequest
>('/premium/stream', (req, res) => handlePremiumStream(req, res));

// Premium Indication
router.post<
  Record<string, never>,
  PremiumIndicateResponse,
  PremiumIndicateRequest
>('/premium/indicate', (req, res) => handlePremiumIndicate(req, res));

// Submission Status
router.get<
  { submissionId: string },
  SubmissionStatusResponse
>('/submission/:submissionId/status', (req, res) => handleSubmissionStatus(req, res));

export const ratingRoutes = router;
