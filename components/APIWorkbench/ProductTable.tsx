'use client'

import { Product } from '@/custom-types'
import useThemeMountedVisible from '@/hooks/useThemeMounted'
import { defaultTheme, formatDate, themeStyles } from '@/lib/utils'
import { EllipsisVertical } from 'lucide-react'
import { Button } from '../ui/button'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger
} from '../ui/sheet'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow
} from '../ui/table'

export interface ProductTableProps {
  products: Product[]
  showActions?: boolean
  onApprove?: () => void
  onDeny?: () => void
}

const ProductTable: React.FC<ProductTableProps> = ({ products }) => {
  const { theme } = useThemeMountedVisible()

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

export default ProductTable
