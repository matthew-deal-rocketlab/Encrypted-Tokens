import { useState } from 'react';
import styled, { css } from 'styled-components';
import Icon from './icons';
import { themeStatic } from '@/theme';

const SelectContainer = styled.div`
  position: relative;
  margin: 0;
`;
const SelectLabelButton = styled.button`
  padding-left: 5px;
  height: 25px;
  width: 100%;
  background-color: ${props => props.theme!.colors.white};
  border-radius: 5px;
  color: ${props => props.theme!.colors.dark};
  border: 1px solid ${props => props.theme!.colors.tertiary};
  cursor: pointer;
  transition: 0.3s ease;
  text-align: left;
  &:hover {
    background-color: #eee;
  }
`;
const DropdownStyle = styled.div<{ $isVisible: boolean }>`
  text-align: left;
  position: absolute;
  top: 0;
  left: 0;
  max-height: 6em;
  width: calc(100% - 12px);
  padding: 0.4rem;
  display: flex;
  flex-direction: column;
  border-radius: 5px;
  background: #fafafa;
  border: 1px solid ${props => props.theme!.colors.tertiary};
  transition: max-height 0.2s ease;
  overflow-y: scroll;
  ${({ $isVisible }) =>
    $isVisible !== true &&
    css`
      max-height: 40px;
      visibility: hidden;
    `}
`;
const DropdownItem = styled.div<{ $active: boolean }>`
  display: flex;
  align-items: center;
  width: 90%;
  margin: 0.15rem 0;
  padding: 0.3rem 0.5rem;
  font-size: 0.9rem;
  font-weight: 400;
  color: #333;
  border-radius: 0.3rem;
  cursor: pointer;
  z-index: ${themeStatic.zIndex.two};
  ${({ $active }) =>
    $active &&
    css`
      color: ${({ theme }) => theme.colors.primary};
      font-weight: ${themeStatic.fontWeight.bold};
    `}
  &:hover, :focus, :focus:hover {
    background-color: ${({ theme }) => theme.colors.primary};
    color: #fafafa;
    outline: none;
  }
`;
const StyledIcon = styled(Icon)`
  position: absolute;
  right: 0.5rem;
  top: 30%;
`;

interface Props {
  label: string;
  values: string[];
  onChange?: (value: string) => void;
}

// TODO: change values to array of objects
// TODO: Close when clicking outside
// TODO: Add error label

const Select = ({ label, values, onChange }: Props) => {
  const [currentValue, setCurrentValue] = useState('');
  const [open, setOpen] = useState(false);
  const handleOpen = () => {
    setOpen(true);
  };
  const handleClose = () => {
    setOpen(false);
  };
  const handleValueChange = (value: string) => {
    setCurrentValue(value);
  };
  const handleChange = (value: string) => {
    handleValueChange(value);
    // call method, if it exists
    if (onChange) {
      onChange(value);
    }
    // close, after all tasks are finished
    handleClose();
  };

  return (
    <SelectContainer>
      <SelectLabelButton onClick={handleOpen}>
        {currentValue !== '' ? currentValue : label}
        <StyledIcon icon="arrow-down" height={10} width={10} />
      </SelectLabelButton>
      <DropdownStyle $isVisible={open}>
        {values.map((value, index) => (
          <DropdownItem
            onClick={() => handleChange(value)}
            $active={value === currentValue}
            key={index}>
            {value}
          </DropdownItem>
        ))}
      </DropdownStyle>
    </SelectContainer>
  );
};

export default Select;