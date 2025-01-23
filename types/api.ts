/**
 * API Product type representing a product in the API Workbench
 */
export interface Product {
  /** Unique identifier for the product */
  id: number
  /** Type of insurance product */
  type: string
  /** Display name of the product */
  name: string
  /** Business category (e.g., Commercial, Personal) */
  lineOfBusiness: string
  /** Date when the product went live */
  liveSince: string
}

/**
 * API User type representing a user in the API Workbench
 */
export interface User {
  /** Unique identifier for the user */
  id: string
  /** Display name of the user/organization */
  name: string
  /** Date when the user joined */
  joinedAt: string
  /** User's email address */
  email: string
  /** User's role (e.g., user, partner) */
  role: string
  /** User's current status (e.g., Active, Revoked) */
  status: string
  /** User's API access key */
  accessKey: string
}

/**
 * Common status values for API users
 */
export type UserStatus = 'Active' | 'Revoked'

/**
 * Common role values for API users
 */
export type UserRole = 'user' | 'partner'
