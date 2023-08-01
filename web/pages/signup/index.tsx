import React from 'react';
import styled from 'styled-components';

import { isEmail } from '@/utils/validators';
import {
  Button,
  Card,
  Form,
  FormInput,
  FormLabel,
  FormRow,
  FormTitle,
  PageLayoutFullPage,
} from '@/components';
import { apiPost } from '@/utils/api-client';
import { ApiStatus } from '@/services/apiclient';
import { ISimpleProps, SubmitResult, SubmitResultType } from '@/types.d';
import { useRouter } from 'next/router';


interface FormFields {
  email: string;
  pass: string;
  firstname: string;
  lastname: string;
  confirmPass: string;
}

const initialFormFields: FormFields = {
  email: '',
  pass: '',
  firstname: '',
  lastname: '',
  confirmPass: '',
};

interface ColoredSpanProps {
  type: SubmitResultType;
  children: string;
}

const ColoredSpan = styled.span<ColoredSpanProps>`
  color: ${props => props.type === SubmitResultType.error ?
    props.theme.colors.error : props.theme.colors.success}
`


// Checks the form inputs.  Returns null for no errors or object with error messages for each field
const validateInputs = (inputs: FormFields): FormFields | null => {
  let hasErrors = false;
  let result = initialFormFields;

  // check email
  if (!inputs.email) {
    hasErrors = true;
    result.email = 'Email can not be empty';
  } else if (!isEmail(inputs.email)) {
    hasErrors = true;
    result.email = 'Invalid Email';
  }
  // check username
  if (!inputs.firstname) {
    hasErrors = true;
    result.firstname = 'Firstname can not be empty';
  }

  // Check password
  if (!inputs.pass) {
    hasErrors = true;
    result.pass = 'Password can not be empty';
  } else if (inputs.pass.length < 8) {
    console.log('Password', result.pass.length);
    hasErrors = true;
    result.pass = 'Password must be at least 8 characters';
  }
  // Check confirm password
  if (!inputs.confirmPass) {
    hasErrors = true;
    result.confirmPass = 'Confirm password can not be empty';
  } else if (inputs.confirmPass.length < 8) {
    hasErrors = true;
    result.confirmPass = 'Confirm password must be at least 8 characters';
  } else if (inputs.confirmPass !== inputs.pass) {
    hasErrors = true;
    result.confirmPass = 'Confirm password must match password';
  }

  return hasErrors ? result : null;
};

const submitFormData = async (data: FormFields): Promise<SubmitResult> => {
  const payload = { authSignup: { ...data, confirmPass: undefined } }
  const loginResult = await apiPost('/jsonql', payload);

  if (loginResult.status !== ApiStatus.OK) {
    return { text: "Error logging in", type: SubmitResultType.error };
  }

  // @ts-ignore
  const authRefreshResult = loginResult.result['authSignup'];

  if (!(authRefreshResult.result && authRefreshResult.result.length === 36)) {
    return { text: authRefreshResult, type: SubmitResultType.error };
  };

  return {
    text: "Welcome! Check your email to continue",
    type: SubmitResultType.ok,
  }
}


const SignupPage = (props: ISimpleProps) => {
  const { push } = useRouter();

  const [showContinue, setShowContinue] = React.useState(false);
  const [submitResult, setSubmitResult] = React.useState<SubmitResult>({ text: '', type: SubmitResultType.ok });
  const [formErrors, setFormErrors] =
    React.useState<FormFields>(initialFormFields);


  const onClickCancel = (event: React.FormEvent<HTMLFormElement>) => {
    push('/login');
  }

  const onClickContinue = (event: React.FormEvent<HTMLFormElement>) => {
    // prevent default form submission
    event.preventDefault();

    push('/login');
  }

  const onClickSignUp = (event: React.FormEvent<HTMLFormElement>) => {
    // prevent default form submission
    event.preventDefault();

    // clear errors when re-submitting
    setSubmitResult(Object.assign({}));
    setFormErrors(Object.assign({}));

    const data = Object.fromEntries(new FormData(event.currentTarget)) as unknown;
    const formData = data as FormFields;
    console.log('data', formData);

    const formErrorMessages = validateInputs(formData);
    console.log('formErrorMessages', formErrorMessages);
    if (formErrorMessages !== null) {
      setFormErrors(Object.assign({}, formErrorMessages));
      return;
    }

    // Submit form data and catch errors in the response
    (async () => {
      const result = await submitFormData(formData);
      setSubmitResult(result);
      setShowContinue(result.type === SubmitResultType.ok)
    })();
  };

  return (
    <PageLayoutFullPage>
      <Card>
        <Form onSubmit={showContinue ? onClickContinue : onClickSignUp}>
          <FormRow align="center">
            <FormTitle>Signup</FormTitle>
          </FormRow>
          <FormRow>
            <FormLabel htmlFor="firstname">First name *</FormLabel>
            <FormInput
              type="text"
              id="firstname"
              name="firstname"
              required
              error={formErrors.firstname}
            />
          </FormRow>
          <FormRow>
            <FormLabel htmlFor="lastname">Last name</FormLabel>
            <FormInput
              type="text"
              id="lastname"
              name="lastname"
              error={formErrors.lastname}
            />
          </FormRow>
          <FormRow>
            <FormLabel htmlFor="email">Email *</FormLabel>
            <FormInput
              type="email"
              id="email"
              name="email"
              required
              error={formErrors.email}
            />
          </FormRow>

          <FormRow>
            <FormLabel htmlFor="pass">Password *</FormLabel>
            <FormInput
              type="password"
              id="pass"
              name="pass"
              required
              error={formErrors.pass}
            />
          </FormRow>

          <FormRow>
            <FormLabel htmlFor="confirmPass">Confirm password *</FormLabel>
            <FormInput
              type="password"
              id="confirmPass"
              name="confirmPass"
              required
              error={formErrors.confirmPass}
            />
          </FormRow>

          <FormRow>
            * Required
          </FormRow>

          <FormRow align='center'>
            <ColoredSpan type={submitResult.type}>
              {submitResult.text}
            </ColoredSpan>
          </FormRow>
          <FormRow fullwidth={false} align="space-between">
            <Button variant="medium" type="submit">
              {showContinue ? 'Continue' : 'Submit'}
            </Button>
            <Button variant="medium" type="button" onClick={onClickCancel}>
              Cancel
            </Button>
          </FormRow>
        </Form>
      </Card>
    </PageLayoutFullPage>
  );
};

export default SignupPage;
