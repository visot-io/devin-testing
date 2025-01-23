import { render, screen, fireEvent } from '@testing-library/react'
import APIWorkbenchPageComponent from '../APIWorkbenchPageComponent'
import { mockProducts, mockUsers } from '../mockData'

describe('APIWorkbenchPageComponent', () => {
  it('renders without crashing', () => {
    render(<APIWorkbenchPageComponent />)
    expect(screen.getByRole('main')).toBeInTheDocument()
  })

  it('displays correct section titles', () => {
    render(<APIWorkbenchPageComponent />)
    expect(screen.getByText('API Workbench')).toBeInTheDocument()
    expect(screen.getByText('Manage Product Access')).toBeInTheDocument()
    expect(screen.getByText('API User Directory')).toBeInTheDocument()
  })

  it('switches between products and users tabs', () => {
    render(<APIWorkbenchPageComponent />)
    
    // Initially shows products tab
    expect(screen.getByText('Products')).toBeInTheDocument()
    
    // Switch to users tab
    fireEvent.click(screen.getByText('Users'))
    expect(screen.getByText('API User Directory')).toBeInTheDocument()
  })

  it('handles product updates', () => {
    const onProductsUpdate = jest.fn()
    render(
      <APIWorkbenchPageComponent
        initialProducts={mockProducts}
        onProductsUpdate={onProductsUpdate}
      />
    )
    
    // TODO: Add more specific product update tests once API integration is complete
  })

  it('handles user updates', () => {
    const onUsersUpdate = jest.fn()
    render(
      <APIWorkbenchPageComponent
        initialUsers={mockUsers}
        onUsersUpdate={onUsersUpdate}
      />
    )
    
    // TODO: Add more specific user update tests once API integration is complete
  })
})
