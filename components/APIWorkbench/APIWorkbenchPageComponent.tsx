'use client'

import SectionTitleSubtitle from '@/components/ui/section-title-subtitle'
import { Product, User, UserTableProps } from '@/custom-types'
import { useSmoothLoading } from '@/hooks/useSmoothLoading'
import useThemeMountedVisible from '@/hooks/useThemeMounted'
import {
  defaultTheme,
  formatDate,
  InputField,
  statusGradients,
  themeStyles
} from '@/lib/utils'
import {
  ArrowUpRight,
  Ban,
  EllipsisVertical,
  Eye,
  EyeOff,
  Plus,
  RotateCcw
} from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { Button } from '../ui/button'
import { Card } from '../ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger
} from '../ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger
} from '../ui/dropdown-menu'
import { Input } from '../ui/input'
import { Label } from '../ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue
} from '../ui/select'
import { Separator } from '../ui/separator'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger
} from '../ui/sheet'
import SubSectionTitleSubtitle from '../ui/sub-section-title-subtitle'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '../ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs'

const products: Product[] = [
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

const generateAccessKey = () => 'ak_' + Math.random().toString(36).slice(2, 24)

interface ProductTableProps {
  products: Product[]
  showActions?: boolean
  onApprove?: () => void
  onDeny?: () => void
}

const ProductTable = ({ products }: ProductTableProps) => {
  const { theme } = useThemeMountedVisible()
  const [users, setUsers] = useState<User[]>([
    {
      id: '1',
      name: 'Lemonade',
      joinedAt: '2023-07-20',
      email: 'john@lemonade.com',
      role: 'user',
      status: 'Active',
      accessKey: generateAccessKey()
    },
    {
      id: '2',
      name: 'PolicyGenius',
      joinedAt: '2023-07-20',
      email: 'jane@policygenius.com',
      role: 'partner',
      status: 'Active',
      accessKey: generateAccessKey()
    },
    {
      id: '3',
      name: 'Cover Genius',
      joinedAt: '2023-07-20',
      email: 'bob@covergenius.com',
      role: 'user',
      status: 'Revoked',
      accessKey: generateAccessKey()
    }
  ])

  const [showAccessKey, setShowAccessKey] = useState<{
    [key: string]: boolean
  }>({})

  const regenerateAccessKey = (id: string) => {
    setUsers(
      users.map(user =>
        user.id === id ? { ...user, accessKey: generateAccessKey() } : user
      )
    )
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
          <TableHead className='w-[200px]'>Name</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Line of Business</TableHead>
          <TableHead>Live Since</TableHead>
          <TableHead className='text-right'>Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {products.map(product => (
          <TableRow key={product.id}>
            <TableCell className='font-medium'>{product.name}</TableCell>
            <TableCell>{product.type}</TableCell>
            <TableCell>{product.lineOfBusiness}</TableCell>
            <TableCell>{formatDate(product.liveSince)}</TableCell>
            <TableCell className='text-right'>
              <Sheet>
                <SheetTrigger asChild>
                  <Button variant='ghost' size='icon'>
                    <EllipsisVertical className='h-4 w-4' />
                  </Button>
                </SheetTrigger>
                <SheetContent>
                  <SheetHeader>
                    <SheetTitle>API Access</SheetTitle>
                  </SheetHeader>
                  <div className='mt-6'>
                    <Table
                      className={`rounded-xl ${themeStyles[theme as 'light' | 'dark']?.gradient3 || themeStyles[defaultTheme]?.gradient3}`}
                    >
                      <TableHeader
                        className={`${theme === 'light' ? 'bg-neutral-200 bg-opacity-45' : 'bg-white bg-opacity-5'} text-xs font-medium`}
                      >
                        <TableRow className='hover:bg-transparent'>
                          <TableHead className='pl-4'>
                            Accessible Products
                          </TableHead>
                          <TableHead className='w-[100px] rounded-tr-xl text-center'>
                            Actions
                          </TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody className='p-6'>
                        {['General Liability', 'Cyber'].map(p => (
                          <TableRow className='hover:bg-transparent' key={p}>
                            <TableCell className='pl-4'>{p}</TableCell>
                            <TableCell>
                              <Button
                                variant={'link'}
                                className='text-sm text-red-600'
                              >
                                Revoke
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </SheetContent>
              </Sheet>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

const InviteNewUserDialog = () => {
  const [isOpen, setIsOpen] = useState(false)

  const handleInvite = () => {
    setIsOpen(false)
    toast('API Consumer Added!', {
      description:
        'The new API consumer has been added successfully. The access key will be shared securely with them.'
    })
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
                {['General Liability', 'Cyber', 'Health'].map(p => (
                  <SelectItem key={p} value={p}>
                    <p>{p}</p>
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

const APIWorkbenchPageComponent = () => {
  const isContentReady = useSmoothLoading(false, true, false)
  const { mounted } = useThemeMountedVisible()
  if (!mounted) return null

  return (
    <div
      className={`flex flex-col transition-opacity duration-500 ${isContentReady ? 'opacity-100' : 'opacity-0'}`}
    >
      <SectionTitleSubtitle
        title={'API Workbench'}
        subtitle={'Manage product access and explore API documentation.'}
      />
      <Tabs defaultValue='products' className='mt-6'>
        <TabsList className='mb-1 h-fit bg-sidebar'>
          <TabsTrigger className='px-6 py-2' value='products'>
            Products
          </TabsTrigger>
          <TabsTrigger className='px-6 py-2' value='users'>
            Users
          </TabsTrigger>
        </TabsList>
        <TabsContent value='products'>
          <Card className='min-h-[500px] p-6'>
            <div className='flex items-center justify-between'>
              <SubSectionTitleSubtitle
                title={'Manage Product Access'}
                subtitle={
                  'View and control API consumers for each product. Regenerate access keys or revoke access as needed.'
                }
              />
              {/* <InviteNewMemberDialog /> */}
            </div>
            <div className='mt-6'>
              <ProductTable products={products} />
            </div>
          </Card>
        </TabsContent>
        <TabsContent value='users'>
          <Card className='min-h-[500px] p-6'>
            <div className='flex items-center justify-between'>
              <SubSectionTitleSubtitle
                title={'API User Directory'}
                subtitle={
                  'Manage API users, their access to products, and add new consumers effortlessly.'
                }
              />
              <InviteNewUserDialog />
            </div>
            <div className='mt-6'>
              <UserViewTable />
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export default APIWorkbenchPageComponent
