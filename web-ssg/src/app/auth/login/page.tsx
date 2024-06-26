'use client'

import { Button } from '@/components/button'
import { isEmail } from '@/utils/validators'
import { type SubmitResult, SubmitResultType, type IAlertMessage } from '@/types.d'
import { apiPost } from '@/utils/api-client'
import { ApiStatus } from '@/services/apiclient'
import { sleep } from '@/utils/sleep'
import { useRouter } from 'next/navigation'
import React from 'react'
import Link from 'next/link'
import Alert from '@/components/alert'
import Input from '@/components/input'
import { KEY_JWT_TOKEN, KEY_REFRESH_TOKEN, passphrase, salt } from '@/constants'
import { encryptToken, deriveKey } from '@/utils/crypto-utils'

interface FormFields {
  email: string
  pass: string
}

type AuthLoginResult = {
  authLogin: {
    token: string
    refreshToken: string
  }
}

const initialFormFields: FormFields = {
  email: '',
  pass: '',
}

// Checks the form inputs.  Returns null for no errors or object with error messages for each field
const validateInputs = (inputs: FormFields): FormFields | null => {
  let hasErrors = false
  const result = { ...initialFormFields }
  console.log('inputs', inputs)
  // check email
  if (!inputs.email) {
    hasErrors = true
    result.email = 'Email can not be empty'
  } else if (!isEmail(inputs.email)) {
    hasErrors = true
    result.email = 'Invalid Email'
  }

  // Check password
  if (!inputs.pass) {
    hasErrors = true
    result.pass = 'Password can not be empty'
  } else if (inputs.pass.length < 6) {
    hasErrors = true
    result.pass = 'Password must be at least 6 characters'
  }

  return hasErrors ? result : null
}

export default function LoginForm() {
  const { push } = useRouter()
  const [formErrors, setFormErrors] = React.useState(initialFormFields)
  const [alert, setAlert] = React.useState<IAlertMessage>({
    message: '',
    type: 'success',
  })

  const setTokens = async (jwtToken: string, refreshToken: string) => {
    const key = await deriveKey(passphrase, salt)

    const { encrypted: encryptedJwt, iv: ivJwt } = await encryptToken(key, jwtToken)
    const { encrypted: encryptedRefresh, iv: ivRefresh } = await encryptToken(key, refreshToken)
    localStorage.setItem(
      KEY_JWT_TOKEN,
      JSON.stringify({
        encryptedJwt: Array.from(new Uint8Array(encryptedJwt)),
        ivJwt: Array.from(new Uint8Array(ivJwt)),
      }),
    )
    localStorage.setItem(
      KEY_REFRESH_TOKEN,
      JSON.stringify({
        encryptedRefresh: Array.from(new Uint8Array(encryptedRefresh)),
        ivRefresh: Array.from(new Uint8Array(ivRefresh)),
      }),
    )
  }
  const submitLoginFormData = async (data: FormFields): Promise<SubmitResult> => {
    const payload = { authLogin: { ...data } }

    const loginResult = await apiPost('/jsonql', payload)

    if (loginResult.status !== ApiStatus.OK) {
      return { text: 'Error logging in', type: SubmitResultType.error }
    }

    const result = loginResult.result as AuthLoginResult
    const authLogin = result.authLogin
    // First, check if authLogin is a string, which indicates an error message.
    if (typeof authLogin === 'string') {
      return { text: authLogin, type: SubmitResultType.error }
    }

    // Next, check if the token is valid.
    if (!authLogin.token || authLogin.token.length <= 20) {
      return { text: 'Invalid login token received.', type: SubmitResultType.error }
    }

    // Use setTokens from context to update auth state
    await setTokens(authLogin.token, authLogin.refreshToken)

    return {
      text: 'Welcome! You will be redirected to the dashboard shortly',
      type: SubmitResultType.success,
    }
  }

  const onClickLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setFormErrors(initialFormFields)
    setAlert({ message: '', type: 'success' })
    const formData = Object.fromEntries(new FormData(event.currentTarget)) as unknown as FormFields

    const formErrorMessages = validateInputs(formData)
    if (formErrorMessages !== null) {
      setFormErrors(formErrorMessages)
      return
    }

    const result = await submitLoginFormData(formData)

    if (result.type === SubmitResultType.error) {
      setAlert({ message: result.text, type: 'error' })
      return
    }
    setAlert({ message: result.text, type: 'success' })
    await sleep(2000)
    push('/dashboard')
  }

  return (
    // eslint-disable-next-line @typescript-eslint/no-misused-promises
    <form onSubmit={onClickLogin} className="space-y-3">
      <div className="flex-1 rounded-lg bg-gray-50 px-6 pb-4 pt-8">
        <h1 className="mb-3 text-2xl">Please log in to continue.</h1>
        <div className="w-full">
          <Input
            id="email"
            type="email"
            name="email"
            label="Email"
            placeholder="Enter your email address"
            formErrors={formErrors.email}
          />
          <div className="mt-4">
            <Input
              id="password"
              type="password"
              name="pass"
              label="Password *"
              placeholder="Enter password"
              formErrors={formErrors.pass}
            />
          </div>
        </div>
        <LoginButton />
        {alert.message && <Alert classes="my-3" type={alert.type} message={alert.message} />}
        <p className="mb-1 mt-4 text-center text-xs">
          Don't have an account?{' '}
          <Link className="text-blue-500" href="/auth/signup" role="link">
            Signup
          </Link>
        </p>
        <p className="mb-1 mt-3 text-center text-xs">
          Forgot your password?{' '}
          <Link className="text-blue-500" href="/auth/forgot-password" role="link">
            Reset Password
          </Link>
        </p>
      </div>
    </form>
  )
}

function LoginButton() {
  return (
    <div className="flex justify-center">
      <Button className="mt-4 w-full max-w-[300px]">Log in</Button>
    </div>
  )
}
