'use client'

import { useSmoothLoading } from '@/hooks/useSmoothLoading'
import useThemeMountedVisible from '@/hooks/useThemeMounted'
import { Product, User } from '../../types/api'
import { Card } from '../ui/card'
import SectionTitleSubtitle from '../ui/section-title-subtitle'
import SubSectionTitleSubtitle from '../ui/sub-section-title-subtitle'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs'
import { ProductTable } from './ProductTable'
import { UserViewTable } from './UserViewTable'
import { InviteNewUserDialog } from './InviteNewUserDialog'
import { mockProducts as products } from './mockData' // TODO: Replace with API integration

/** Props for the APIWorkbenchPageComponent */
export interface APIWorkbenchPageComponentProps {
  /** Initial products data */
  initialProducts?: Product[]
  /** Initial users data */
  initialUsers?: User[]
  /** Callback when products are updated */
  onProductsUpdate?: (products: Product[]) => void
  /** Callback when users are updated */
  onUsersUpdate?: (users: User[]) => void
}

/**
 * Main component for the API Workbench page
 * Manages product access and API user directory
 * @param props Component props
 * @returns React component
 */
const APIWorkbenchPageComponent: React.FC<APIWorkbenchPageComponentProps> = ({
  initialProducts,
  initialUsers,
  onProductsUpdate,
  onUsersUpdate
}) => {
  const isContentReady = useSmoothLoading(false, true, false)
  const { mounted } = useThemeMountedVisible()
  if (!mounted) return null

  return (
    <div
      className={`flex flex-col transition-opacity duration-500 ${isContentReady ? 'opacity-100' : 'opacity-0'}`}
      role="main"
      aria-label="API Workbench"
    >
      <SectionTitleSubtitle
        title={'API Workbench'}
        subtitle={'Manage product access and explore API documentation.'}
      />
      <Tabs defaultValue='products' className='mt-6'>
        <TabsList className='mb-1 h-fit bg-sidebar' aria-label="Workbench sections">
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
            </div>
            <div className='mt-6'>
              <ProductTable
                products={initialProducts || products}
                onApprove={(productId) => onProductsUpdate?.(products)}
                onDeny={(productId) => onProductsUpdate?.(products)}
              />
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
              <InviteNewUserDialog onInvite={(formData) => {
                // TODO: Replace with API integration
                console.log('New user invited:', formData)
              }} />
            </div>
            <div className='mt-6'>
              <UserViewTable
                initialUsers={initialUsers}
                onUserUpdate={onUsersUpdate}
              />
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}

export default APIWorkbenchPageComponent
