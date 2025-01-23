import { render, screen, fireEvent } from '@testing-library/react'
import { UserViewTable } from '../UserViewTable'
import { mockUsers } from '../mockData'

describe('UserViewTable', () => {
  const defaultProps = {
    initialUsers: mockUsers,
    onUserUpdate: jest.fn()
  }

  it('renders all users', () => {
    render(<UserViewTable {...defaultProps} />)
    
    mockUsers.forEach(user => {
      expect(screen.getByText(user.name)).toBeInTheDocument()
      expect(screen.getByText(user.email)).toBeInTheDocument()
      expect(screen.getByText(user.role)).toBeInTheDocument()
      expect(screen.getByText(user.status)).toBeInTheDocument()
    })
  })

  it('toggles access key visibility', () => {
    render(<UserViewTable {...defaultProps} />)
    
    const toggleButtons = screen.getAllByRole('button', { name: /show|hide/i })
    fireEvent.click(toggleButtons[0])
    
    expect(screen.getByText(mockUsers[0].accessKey)).toBeInTheDocument()
  })

  it('regenerates access key', () => {
    const onUserUpdate = jest.fn()
    render(<UserViewTable {...defaultProps} onUserUpdate={onUserUpdate} />)
    
    const regenerateButtons = screen.getAllByRole('button', { name: /regenerate/i })
    fireEvent.click(regenerateButtons[0])
    
    expect(onUserUpdate).toHaveBeenCalled()
  })

  it('copies access key to clipboard', async () => {
    const mockClipboard = {
      writeText: jest.fn()
    }
    Object.assign(navigator, { clipboard: mockClipboard })
    
    render(<UserViewTable {...defaultProps} />)
    
    const toggleButtons = screen.getAllByRole('button', { name: /show|hide/i })
    fireEvent.click(toggleButtons[0])
    
    const copyButtons = screen.getAllByRole('button', { name: /copy/i })
    fireEvent.click(copyButtons[0])
    
    expect(mockClipboard.writeText).toHaveBeenCalledWith(mockUsers[0].accessKey)
  })
})
