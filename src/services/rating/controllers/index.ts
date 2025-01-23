import { Request, Response } from 'express';
import {
  KnockoutAssessmentRequest,
  KnockoutAssessmentResponse,
  PremiumCalculationRequest,
  PremiumCalculationResponse,
  PremiumStreamRequest,
  PremiumStreamResponse,
  PremiumIndicateRequest,
  PremiumIndicateResponse,
  SubmissionStatusResponse,
} from '../types';

// Controller placeholder implementations with sample responses
export const handleKnockoutAssessment = (
  req: Request<
    Record<string, never>,
    Record<string, never>,
    KnockoutAssessmentRequest
  >,
  res: Response<KnockoutAssessmentResponse>,
) => {
  const sampleResponse: KnockoutAssessmentResponse = {
    submissionId: req.body.submissionId,
    status: 'ACCEPTED',
    reasons: [
      {
        code: 'INDUSTRY_ELIGIBLE',
        description: 'Industry meets eligibility criteria',
        severity: 'INFO',
      },
    ],
    nextSteps: {
      allowPremiumCalculation: true,
      requiredDocuments: ['FINANCIAL_STATEMENTS', 'CLAIMS_HISTORY'],
      referralInstructions: '',
    },
  };
  res.json(sampleResponse);
};

export const handlePremiumCalculation = (
  req: Request<
    Record<string, never>,
    Record<string, never>,
    PremiumCalculationRequest
  >,
  res: Response<PremiumCalculationResponse>,
) => {
  const sampleResponse: PremiumCalculationResponse = {
    submissionId: req.body.submissionId,
    calculationId: '12345',
    premium: {
      basePremium: 1000,
      adjustments: [
        {
          type: 'EXPERIENCE_CREDIT',
          factor: 0.95,
          amount: -50,
          description: 'Good claims history',
        },
      ],
      totalPremium: 950,
    },
    breakdown: {
      exposureBase: 1000000,
      baseRate: 0.001,
      modifiers: [
        {
          name: 'INDUSTRY_FACTOR',
          value: 1.1,
        },
      ],
    },
  };
  res.json(sampleResponse);
};

export const handlePremiumStream = (
  req: Request<
    Record<string, never>,
    Record<string, never>,
    PremiumStreamRequest
  >,
  res: Response,
) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sampleUpdate: PremiumStreamResponse = {
    event: 'premium_update',
    data: {
      submissionId: req.body.submissionId,
      timestamp: new Date().toISOString(),
      indicativePremium: {
        minimum: 900,
        maximum: 1100,
        estimated: 1000,
      },
      confidence: 'HIGH',
      questionId: 'REVENUE_Q1',
    },
  };

  res.write(`data: ${JSON.stringify(sampleUpdate)}\n\n`);
};

export const handlePremiumIndicate = (
  req: Request<Record<string, never>, Record<string, never>, PremiumIndicateRequest>,
  res: Response<PremiumIndicateResponse>,
) => {
  const sampleResponse: PremiumIndicateResponse = {
    submissionId: req.body.submissionId,
    indicativePremium: {
      minimum: 900,
      maximum: 1100,
      estimated: 1000,
    },
    confidence: 'MEDIUM',
    missingFactors: [
      {
        code: 'CLAIMS_HISTORY',
        description: 'Claims history information required',
        impact: 'HIGH',
      },
    ],
  };
  res.json(sampleResponse);
};

export const handleSubmissionStatus = (
  req: Request<{ submissionId: string }>,
  res: Response<SubmissionStatusResponse>,
) => {
  const { submissionId } = req.params;
  const sampleResponse: SubmissionStatusResponse = {
    submissionId,
    status: 'IN_PROGRESS',
    knockoutAssessment: {
      submissionId,
      status: 'ACCEPTED',
      reasons: [],
      nextSteps: {
        allowPremiumCalculation: true,
        requiredDocuments: [],
        referralInstructions: '',
      },
    },
    premiumCalculations: [
      {
        calculationId: '12345',
        timestamp: new Date().toISOString(),
        version: '1.0',
        result: {
          totalPremium: 950,
        },
      },
    ],
    timeline: [
      {
        timestamp: new Date().toISOString(),
        event: 'SUBMISSION_CREATED',
        details: {},
      },
    ],
  };
  res.json(sampleResponse);
};
