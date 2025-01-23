'use client'

import { useState } from 'react'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'

import { InputField } from '@/lib/utils'

import { Button } from '../ui/button'
import { mockProducts } from './mockData'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '../ui/dialog'
import { Label } from '../ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '../ui/select'

/** Form data structure for new user invitation */
interface InviteFormData {
  /** Selected product type */
  product: string
  /** User/organization name */
  name: string
  /** User email address */
  email: string
}

/** Props for the InviteNewUserDialog component */
export interface InviteNewUserDialogProps {
  /** Callback when a new user is successfully invited */
  onInvite?: (formData: InviteFormData) => void
}

/**
 * Dialog component for inviting new API users
 * @param props Component props
 * @returns React component
 */
const InviteNewUserDialog: React.FC<InviteNewUserDialogProps> = ({ onInvite }) => {
  const [isOpen, setIsOpen] = useState(false)
  const [formData, setFormData] = useState<InviteFormData>({
    product: '',
    name: '',
    email: ''
  })

  /**
   * Updates form data when fields change
   */
  const handleFieldChange = (field: keyof InviteFormData, value: string): void => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  /**
   * Handles form submission and user invitation
   */
  const handleInvite = (): void => {
    // Validate required fields
    if (!formData.product || !formData.name || !formData.email) {
      toast('Please fill in all fields', {
        description: 'All fields are required to create a new API user.'
      })
      return
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    if (!emailRegex.test(formData.email)) {
      toast('Invalid email format', {
        description: 'Please enter a valid email address.'
      })
      return
    }

    setIsOpen(false)
    toast('API Consumer Added!', {
      description:
        'The new API consumer has been added successfully. The access key will be shared securely with them.'
    })
    onInvite?.(formData)
    
    // Reset form
    setFormData({
      product: '',
      name: '',
      email: ''
    })
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button aria-label="Add new API user">
          <Plus /> New API User
        </Button>
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Add New API User</DialogTitle>
          <DialogDescription>
            Grant access and generate a unique API key for seamless integration.
          </DialogDescription>
        </DialogHeader>
        <div className='mt-4 flex flex-col gap-6'>
          <div className='flex w-full flex-col space-y-2'>
            <Label htmlFor="product-select">Product</Label>
            <Select
              value={formData.product}
              onValueChange={(value) => handleFieldChange('product', value)}
            >
              <SelectTrigger id="product-select" className='h-10'>
                <SelectValue placeholder='-- Select Product --' />
              </SelectTrigger>
              <SelectContent>
                {/* TODO: Replace with API integration */}
                {mockProducts.map(p => (
                  <SelectItem key={p.id} value={p.type}>
                    <p>{p.name}</p>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <InputField
            id="user-name"
            label='Name'
            placeholder="Enter the user's name"
            value={formData.name}
            onChange={(e) => handleFieldChange('name', e.target.value)}
            required
            aria-label="User name"
          />
          <InputField
            id="user-email"
            label='Email'
            placeholder="Enter the user's email"
            value={formData.email}
            onChange={(e) => handleFieldChange('email', e.target.value)}
            type="email"
            required
            aria-label="User email"
          />
        </div>
        <div className='ml-auto mt-4 flex gap-2'>
          <Button
            variant='secondary'
            onClick={() => setIsOpen(false)}
            aria-label="Cancel adding new user"
          >
            Cancel
          </Button>
          <Button
            onClick={handleInvite}
            aria-label="Add new user"
          >
            Add
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default InviteNewUserDialog
