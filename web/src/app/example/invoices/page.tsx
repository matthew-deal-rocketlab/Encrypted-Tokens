import React, { Suspense } from 'react'
import Pagination from '@/components/examples/invoices/pagination'
import Search from '@/components/examples/invoices/search'
import Table from '@/components/examples/invoices/table'
import { CreateInvoice } from '@/components/examples/invoices/buttons'
import { InvoicesTableSkeleton } from '@/components/examples/skeletons'
import { apiPost } from '@/utils/api-client'
import { SubmitResultType } from '@/types.d'
import { ApiStatus } from '@/services/apiclient'

const fetchInvoicePagesData = async (query: string) => {
  const invoiceData = await apiPost('/jsonql', {
    fetchInvoicesPages: { query },
  })

  if (invoiceData.status !== ApiStatus.OK) {
    return { text: 'Error logging in', type: SubmitResultType.error }
  }
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-expect-error
  const { fetchInvoicesPages } = invoiceData.result

  return fetchInvoicesPages
}

export default async function Page({
  searchParams,
}: {
  searchParams?: {
    query?: string
    page?: string
  }
}) {
  const query = searchParams?.query ?? ''
  const currentPage = Number(searchParams?.page) || 1

  console.log('searchParams', searchParams)

  const pages = await fetchInvoicePagesData(query)

  return (
    <div className="w-full">
      <div className="flex w-full items-center justify-between">
        <h1 className="text-2xl">Invoices</h1>
      </div>
      <div className="mt-4 flex items-center justify-between gap-2 md:mt-8">
        <Search placeholder="Search invoices..." />
        <CreateInvoice />
      </div>
      <Suspense key={query + currentPage} fallback={<InvoicesTableSkeleton />}>
        <Table query={query} currentPage={currentPage} />
      </Suspense>
      <div className="mt-5 flex w-full justify-center">
        <Pagination totalPages={pages} />
      </div>
    </div>
  )
}
