import React from 'react';
import styled, { DefaultTheme, StyleSheetManager } from 'styled-components';

import { themeStatic } from '@/theme';

interface ButtonProps {
  children: React.ReactNode;
  variant: 'small' | 'medium' | 'large';
  bgColor?: string;
  type?: 'submit' | 'reset' | 'button';
  theme?: DefaultTheme;
  onClick?: (e?: any) => void;
  onKeyDown?: (e: React.KeyboardEvent<HTMLButtonElement>) => void;
}

// Create a styled component for the button
const buttonPadX = {
  small: '2px',
  medium: '4px',
  large: '6px',
};

const buttonPadY = {
  small: '4px',
  medium: '8px',
  large: '10px',
};

const StyledButton = styled.button<ButtonProps>`
  border-radius: 4px;
  padding: ${(props: ButtonProps) => {
    const px = buttonPadX[props.variant] || buttonPadX['medium'];
    const py = buttonPadY[props.variant] || buttonPadY['medium'];
    return `${py} ${px}`;
  }};
  color: white;
  background-color: ${(props: ButtonProps) =>
    props.bgColor || props.theme!.colors.primary};
  font-family: ${themeStatic.font};
`;

const Button = ({
  variant = 'medium',
  type = 'button',
  ...restProps
}: ButtonProps) => {
  return (
    <StyleSheetManager
      shouldForwardProp={prop => ['variant'].indexOf(prop) < 0}>
      <StyledButton x-name="Button" variant={variant} {...restProps} />
    </StyleSheetManager>
  );
};

export default Button;
