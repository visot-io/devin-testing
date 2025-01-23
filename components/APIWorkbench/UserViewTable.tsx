'use client'

import { User } from '@/custom-types'
import useThemeMountedVisible from '@/hooks/useThemeMounted'
import { defaultTheme, themeStyles } from '@/lib/utils'
import { Eye, EyeOff, RotateCcw } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
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

export interface UserViewTableProps {
  initialUsers?: User[]
  onUserUpdate?: (users: User[]) => void
}

const UserViewTable: React.FC<UserViewTableProps> = ({ initialUsers, onUserUpdate }) => {
  const { theme } = useThemeMountedVisible()
  // TODO: Replace with API integration
  const [users, setUsers] = useState<User[]>(initialUsers || mockUsers)

  const [showAccessKey, setShowAccessKey] = useState<{
    [key: string]: boolean
  }>({})

  const regenerateAccessKey = (id: string) => {
    const updatedUsers = users.map(user =>
      user.id === id ? { ...user, accessKey: generateAccessKey() } : user
    )
    setUsers(updatedUsers)
    onUserUpdate?.(updatedUsers)
    toast('Access Key Regenerated', {
      description: 'A new access key has been generated for the user.'
    })
  }

  const copyAccessKey = (accessKey: string) => {
    navigator.clipboard.writeText(accessKey)
    toast('Access Key Copied', {
      description: 'The access key has been copied to your clipboard.'
    })
  }

  const toggleShowAccessKey = (id: string) => {
    setShowAccessKey(prev => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <Table
      className={`rounded-xl ${themeStyles[theme as 'light' | 'dark']?.gradient3 || themeStyles[defaultTheme]?.gradient3}`}
    >
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
