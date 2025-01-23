import { render, screen, fireEvent } from '@testing-library/react'
import { InviteNewUserDialog } from '../InviteNewUserDialog'
import { mockProducts } from '../mockData'

describe('InviteNewUserDialog', () => {
  const defaultProps = {
    onInvite: jest.fn()
  }

  it('renders dialog trigger button', () => {
    render(<InviteNewUserDialog {...defaultProps} />)
    expect(screen.getByRole('button', { name: /add new api user/i })).toBeInTheDocument()
  })

  it('opens dialog on button click', () => {
    render(<InviteNewUserDialog {...defaultProps} />)
    
    fireEvent.click(screen.getByRole('button', { name: /add new api user/i }))
    
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByText('Add New API User')).toBeInTheDocument()
  })

  it('validates required fields', () => {
    render(<InviteNewUserDialog {...defaultProps} />)
    
    fireEvent.click(screen.getByRole('button', { name: /add new api user/i }))
    fireEvent.click(screen.getByRole('button', { name: /add/i }))
    
    expect(screen.getByText('Please fill in all fields')).toBeInTheDocument()
  })

  it('validates email format', () => {
    render(<InviteNewUserDialog {...defaultProps} />)
    
    fireEvent.click(screen.getByRole('button', { name: /add new api user/i }))
    
    // Fill in invalid form data
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'Test User' } })
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'invalid-email' } })
    fireEvent.click(screen.getByRole('button', { name: /add/i }))
    
    expect(screen.getByText('Invalid email format')).toBeInTheDocument()
  })

  it('submits form with valid data', () => {
    const onInvite = jest.fn()
    render(<InviteNewUserDialog onInvite={onInvite} />)
    
    fireEvent.click(screen.getByRole('button', { name: /add new api user/i }))
    
    // Fill in valid form data
    fireEvent.change(screen.getByLabelText(/name/i), { target: { value: 'Test User' } })
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: 'test@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /add/i }))
    
    expect(onInvite).toHaveBeenCalledWith({
      name: 'Test User',
      email: 'test@example.com',
      product: expect.any(String)
    })
  })
})
