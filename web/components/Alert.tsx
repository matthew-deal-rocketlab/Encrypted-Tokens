//write a alert component that will be used to display alerts to the user
//similar to alert from material ui
//should accept a type prop that will determine the color of the alert

import { themeStatic } from '@/theme';
import { ReactNode } from 'react';
import styled, { useTheme } from 'styled-components';
import Icon, { BarsIcon, XMarkIcon } from './icons';
import { ColorType } from '@/types';

// make a style for the alert

const StyledAlert = styled.div<{ type: string }>`
  width: 100%;
  height: 30px;
  background-color: ${({ theme, type }) => theme.colors[type].light};
  border-radius: 5px;
  border-left: 5px solid ${({ theme, type }) => theme.colors[type].main};
  color: ${({ theme, type }) => theme.colors[type].dark};
  margin: 0;
  font-size: ${({ theme }) => themeStatic.fontSizes.small};
  display: grid;
`;
const Container = styled.div`
  align-items: center;
  display: grid;
  grid-template-columns: 30px 10fr 20px;
  margin-left: 10px;
`;

interface Props {
  type: ColorType;
  children: ReactNode;
  onClose?: () => void;
}

const Alert = ({ type, children, onClose }: Props) => {
  const theme = useTheme();
  return (
    <StyledAlert type={type}>
      <Container>
        <Icon
          icon={type}
          height={18}
          width={18}
          fill={theme.colors[type].dark}
        />
        {children}
        <XMarkIcon
          height={10}
          width={10}
          fill={theme.colors[type].dark}
          onClick={onClose}
        />
      </Container>
    </StyledAlert>
  );
};

export default Alert;