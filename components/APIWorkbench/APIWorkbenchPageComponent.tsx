'use client'

import SectionTitleSubtitle from '@/components/ui/section-title-subtitle'
import { Product } from '@/custom-types'
import { useSmoothLoading } from '@/hooks/useSmoothLoading'
import useThemeMountedVisible from '@/hooks/useThemeMounted'
import { Card } from '../ui/card'
import SubSectionTitleSubtitle from '../ui/sub-section-title-subtitle'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../ui/tabs'
import { ProductTable } from './ProductTable'
import { UserViewTable } from './UserViewTable'
import { InviteNewUserDialog } from './InviteNewUserDialog'

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
