import { Product, User } from '../../types/api'

// TODO: Replace with API integration
// Example API endpoint: /api/products
export const mockProducts: Product[] = [
  {
    id: 1,
    type: 'General Liability',
    name: 'Chubb-GL',
    lineOfBusiness: 'Commercial',
    liveSince: '2021-01-01'
  },
  {
    id: 2,
    type: 'Cyber',
    name: 'Chubb-CY',
    lineOfBusiness: 'Commercial',
    liveSince: '2020-06-15'
  },
  {
    id: 3,
    type: 'Health',
    name: 'Chubb-HEALTH',
    lineOfBusiness: 'Personal',
    liveSince: '2022-03-10'
  }
]

// TODO: Replace with API integration
// Example API endpoint: /api/users
export const mockUsers: User[] = [
  {
    id: '1',
    name: 'Lemonade',
    joinedAt: '2023-07-20',
    email: 'john@lemonade.com',
    role: 'user',
    status: 'Active',
    accessKey: 'ak_mock1'
  },
  {
    id: '2',
    name: 'PolicyGenius',
    joinedAt: '2023-07-20',
    email: 'jane@policygenius.com',
    role: 'partner',
    status: 'Active',
    accessKey: 'ak_mock2'
  },
  {
    id: '3',
    name: 'Cover Genius',
    joinedAt: '2023-07-20',
    email: 'bob@covergenius.com',
    role: 'user',
    status: 'Revoked',
    accessKey: 'ak_mock3'
  }
]

// Utility function for generating access keys
// TODO: Move to a secure key generation service
export const generateAccessKey = () => 'ak_' + Math.random().toString(36).slice(2, 24)
