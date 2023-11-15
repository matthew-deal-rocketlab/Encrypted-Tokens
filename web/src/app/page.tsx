import React from 'react'
import Link from 'next/link'

export default function Home() {
  return (
    // TODO: Create a Login component that will be used to login to the dashboard
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <Link href="/auth/login">
        <button>Login to dashboard</button>
      </Link>
    </main>
  )
}
