import React, { ReactNode } from 'react';
import styled, { StyleSheetManager } from 'styled-components';

import { themeStatic } from '@/theme';

interface FormRowProps {
  align?: 'left' | 'center' | 'right' | 'space-between';
  fullwidth?: boolean;
  children: ReactNode;
  width?: string;
}
const StyledFormRow = styled.div<FormRowProps>`
  width: ${props => props.width || '100%'};
  @media (max-width: ${themeStatic.breakpoints.mobile}) {
    width: 100%;
  }
  margin-top: ${themeStatic.spacing.formfieldY};
  margin-bottom: ${themeStatic.spacing.formfieldY};
  display: ${(props: FormRowProps) => props.fullwidth ? 'flex' : 'inline-flex'};
  flex-direction: ${(props: FormRowProps) => props.align === 'space-between' ? 'row' : 'column'};
  justify-content: ${(props: FormRowProps) => props.align};
  text-align: ${(props: FormRowProps) => props.align};
`;

const FormRow = ({
  align = 'left',
  fullwidth = true,
  ...props
}: FormRowProps) => {
  return (
    <StyleSheetManager
      shouldForwardProp={prop => ['align', 'fullwidth'].indexOf(prop) < 0}>
      <StyledFormRow
        x-name="FormRow"
        align={align}
        fullwidth={fullwidth}
        {...props}
      />
    </StyleSheetManager>
  );
};

export default FormRow;