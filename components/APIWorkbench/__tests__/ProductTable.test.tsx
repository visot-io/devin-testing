import { render, screen, fireEvent } from '@testing-library/react'
import { ProductTable } from '../ProductTable'
import { mockProducts } from '../mockData'

describe('ProductTable', () => {
  const defaultProps = {
    products: mockProducts,
    onApprove: jest.fn(),
    onDeny: jest.fn()
  }

  it('renders all products', () => {
    render(<ProductTable {...defaultProps} />)
    
    mockProducts.forEach(product => {
      expect(screen.getByText(product.name)).toBeInTheDocument()
      expect(screen.getByText(product.type)).toBeInTheDocument()
      expect(screen.getByText(product.lineOfBusiness)).toBeInTheDocument()
    })
  })

  it('opens product details sheet', () => {
    render(<ProductTable {...defaultProps} />)
    
    // Click the first product's action button
    const actionButtons = screen.getAllByRole('button', { name: /actions/i })
    fireEvent.click(actionButtons[0])
    
    expect(screen.getByText('API Access')).toBeInTheDocument()
    expect(screen.getByText('Accessible Products')).toBeInTheDocument()
  })

  it('handles product approval', () => {
    const onApprove = jest.fn()
    render(<ProductTable {...defaultProps} onApprove={onApprove} />)
    
    // TODO: Add approval flow tests once API integration is complete
  })

  it('handles product denial', () => {
    const onDeny = jest.fn()
    render(<ProductTable {...defaultProps} onDeny={onDeny} />)
    
    // TODO: Add denial flow tests once API integration is complete
  })
})
