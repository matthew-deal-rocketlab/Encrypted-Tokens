import React from 'react'
import TopNav from '@/components/dashboard/topNav/top-nav'
import SideNav from '@/components/dashboard/sideNav/sidenav'

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen flex-col">
      <TopNav />
      <div className="flex flex-1 overflow-hidden md:flex-row">
        <SideNav />
        <div className="flex-grow overflow-y-auto p-6 md:p-12">{children}</div>
      </div>
    </div>
  )
}

export default Layout
