'use client'

import { useState } from 'react'
import { Eye, EyeOff, RotateCcw } from 'lucide-react'
import { toast } from 'sonner'

import { User } from '../../types/api'
import useThemeMountedVisible from '@/hooks/useThemeMounted'
import { defaultTheme, themeStyles } from '@/lib/utils'

import { Button } from '../ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '../ui/table'

import { generateAccessKey, mockUsers } from './mockData'

/** Type for tracking visibility state of access keys */
interface AccessKeyVisibility {
  [key: string]: boolean
}

/** Props for the UserViewTable component */
export interface UserViewTableProps {
  /** Initial array of users to display */
  initialUsers?: User[]
  /** Callback when users are updated */
  onUserUpdate?: (users: User[]) => void
}

/**
 * UserViewTable displays a list of API users with their access keys and management controls
 * @param props Component props
 * @returns React component
 */
const UserViewTable: React.FC<UserViewTableProps> = ({ initialUsers, onUserUpdate }) => {
  const { theme } = useThemeMountedVisible()
  const currentTheme = theme as 'light' | 'dark'
  
  // TODO: Replace with API integration
  const [users, setUsers] = useState<User[]>(initialUsers || mockUsers)
  const [showAccessKey, setShowAccessKey] = useState<AccessKeyVisibility>({})

  /**
   * Generates a new access key for the specified user
   * @param id User ID
   */
  const regenerateAccessKey = (id: string): void => {
    const updatedUsers = users.map(user =>
      user.id === id ? { ...user, accessKey: generateAccessKey() } : user
    )
    setUsers(updatedUsers)
    onUserUpdate?.(updatedUsers)
    toast('Access Key Regenerated', {
      description: 'A new access key has been generated for the user.'
    })
  }

  /**
   * Copies the access key to clipboard
   * @param accessKey Access key to copy
   */
  const copyAccessKey = (accessKey: string): void => {
    navigator.clipboard.writeText(accessKey)
    toast('Access Key Copied', {
      description: 'The access key has been copied to your clipboard.'
    })
  }

  /**
   * Toggles visibility of an access key
   * @param id User ID
   */
  const toggleShowAccessKey = (id: string): void => {
    setShowAccessKey(prev => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <Table
      className={`rounded-xl ${themeStyles[currentTheme]?.gradient3 || themeStyles[defaultTheme]?.gradient3}`}
      aria-label="API Users table"
      <TableHeader
        className={`${theme === 'light' ? 'bg-neutral-100' : 'bg-white bg-opacity-5'} text-xs font-medium`}
      >
        <TableRow>
          <TableHead>Name</TableHead>
          <TableHead>Email</TableHead>
          <TableHead>Role</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Access Key</TableHead>
          <TableHead className='text-right'>Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {users.map(user => (
          <TableRow key={user.id}>
            <TableCell className='font-medium'>{user.name}</TableCell>
            <TableCell>{user.email}</TableCell>
            <TableCell>{user.role}</TableCell>
            <TableCell>{user.status}</TableCell>
            <TableCell className='flex items-center gap-2'>
              <span className='font-mono'>
                {showAccessKey[user.id] ? user.accessKey : '••••••••••••'}
              </span>
              <Button
                variant='ghost'
                size='icon'
                onClick={() => toggleShowAccessKey(user.id)}
              >
                {showAccessKey[user.id] ? (
                  <EyeOff className='h-4 w-4' />
                ) : (
                  <Eye className='h-4 w-4' />
                )}
              </Button>
              <Button
                variant='ghost'
                size='icon'
                onClick={() => copyAccessKey(user.accessKey)}
              >
                <RotateCcw className='h-4 w-4' />
              </Button>
            </TableCell>
            <TableCell className='text-right'>
              <Button
                variant='ghost'
                onClick={() => regenerateAccessKey(user.id)}
              >
                Regenerate Key
              </Button>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

export default UserViewTable
