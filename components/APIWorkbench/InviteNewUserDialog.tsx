'use client'

import { InputField } from '@/lib/utils'
import { mockProducts } from './mockData'
import { Plus } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Button } from '../ui/button'
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

export interface InviteNewUserDialogProps {
  onInvite?: () => void
}

const InviteNewUserDialog: React.FC<InviteNewUserDialogProps> = ({ onInvite }) => {
  const [isOpen, setIsOpen] = useState(false)

  const handleInvite = () => {
    setIsOpen(false)
    toast('API Consumer Added!', {
      description:
        'The new API consumer has been added successfully. The access key will be shared securely with them.'
    })
    onInvite?.()
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>
        <Button>
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
            <Label>Product</Label>
            <Select>
              <SelectTrigger className='h-10'>
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
          <InputField label='Name' placeholder="Enter the user's name" />
          <InputField label='Email' placeholder="Enter the user's email" />
        </div>
        <div className='ml-auto mt-4 flex gap-2'>
          <Button variant='secondary' onClick={() => setIsOpen(false)}>
            Cancel
          </Button>
          <Button onClick={handleInvite}>Add</Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default InviteNewUserDialog
