// Common Types
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown;
    correlationId: string;
  };
}

// Knockout Assessment Types
export interface KnockoutAssessmentRequest {
  submissionId: string;
  productCode: string;
  questionnaireVersion: string;
  answers: {
    industryCode: string;
    yearsInBusiness: number;
    answers: Array<{
      questionId: string;
      value: string | number | boolean | null;
    }>;
  };
}

export interface KnockoutAssessmentResponse {
  submissionId: string;
  status: 'ACCEPTED' | 'REJECTED' | 'REFER';
  reasons: Array<{
    code: string;
    description: string;
    severity: 'INFO' | 'WARNING' | 'ERROR';
  }>;
  nextSteps: {
    allowPremiumCalculation: boolean;
    requiredDocuments: string[];
    referralInstructions: string;
  };
}

// Premium Calculation Types
export interface PremiumCalculationRequest {
  submissionId: string;
  productCode: string;
  ratingFactors: {
    industryCode: string;
    exposure: {
      type: 'REVENUE' | 'PAYROLL' | 'AREA';
      value: number;
    };
    location: {
      country: string;
      state: string;
      zipCode: string;
    };
    additionalFactors: Record<string, string | number | boolean | null>;
  };
  questionnaireAnswers: KnockoutAssessmentRequest['answers'];
}

export interface PremiumCalculationResponse {
  submissionId: string;
  calculationId: string;
  premium: {
    basePremium: number;
    adjustments: Array<{
      type: string;
      factor: number;
      amount: number;
      description: string;
    }>;
    totalPremium: number;
  };
  breakdown: {
    exposureBase: number;
    baseRate: number;
    modifiers: Array<{
      name: string;
      value: number;
    }>;
  };
}

// Premium Stream Types
export interface PremiumStreamRequest {
  submissionId: string;
  productCode: string;
  sessionId: string;
}

export interface PremiumStreamResponse {
  event: 'premium_update';
  data: {
    submissionId: string;
    timestamp: string;
    indicativePremium: {
      minimum: number;
      maximum: number;
      estimated: number;
    };
    confidence: 'HIGH' | 'MEDIUM' | 'LOW';
    questionId: string;
  };
}
