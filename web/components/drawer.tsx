import React, { useState } from 'react';
import styled from 'styled-components';
import { IMenuItem } from './types';
import { menuItems } from '@/utils/data';
import { themeStatic } from '@/theme';

const DrawerContainer = styled.div<{ $isDrawerOpen: boolean }>`
  text-align: center;
  height: 100vh;
  width: 50%;
  position: absolute;
  z-index: 1;
  top: 0;
  right: 0;
  background-color: ${({ theme }) => theme.colors.dark2};
  overflow-x: hidden;
  transform: translateX(${({ $isDrawerOpen }) => ($isDrawerOpen ? 0 : 100)}%);
  transition: transform 0.5s;
  @media (min-width: ${themeStatic.breakpoints.mobile}) {
    width: 30%;
  }
  @media (min-width: ${themeStatic.breakpoints.tablet}) {
    width: 15%;
  }
`;

// REFACTOR: use or create reusable components
const Title = styled.h1`
  font-size: ${themeStatic.fontSizes.xlarge};
  padding: 500px 0x;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.titleText};
`;

const MenuItem = styled.div<{ $isActive: boolean }>`
  background-color: ${({ $isActive, theme }) =>
    $isActive ? theme.colors.dark : theme.colors.dark2};
  padding: 10px 0;
  cursor: pointer;
  margin: 1px 0;
  border-bottom: 1px solid ${({ theme }) => theme.colors.dark};
  &:hover {
    background-color: ${({ theme }) => theme.colors.dark};
  }
  &:focus {
    outline: none;
  }
`;

const GroupMenuItem = styled(MenuItem)`
  display: grid;
  grid-template-columns: 90% 10%;
  justify-content: space-between;
  align-items: center;
  text-align: center;
  padding-left: 10%;
`;

// REFACTOR: use a button component
const Button = styled.button`
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: ${({ theme }) => theme.colors.primary};
  color: ${({ theme }) => theme.colors.buttonText};
  border: none;
  border-radius: 5px;
  padding: 10px 20px;
  cursor: pointer;
  transition: all 0.2s ease-in-out;

  &:hover {
    background-color: ${({ theme }) => theme.colors.secondary};
  }
  &:focus {
    outline: none;
  }
`;

const MenuItemContainer = styled.div`
  display: block;
  overflow: hidden;
`;

// REFACTOR: Use a arrow image
const Arrow = styled.div<{ isOpen: boolean }>`
  background-repeat: no-repeat;
  background-size: cover;
  align-self: flex-end;
  margin-left: -50%;
  rotate: ${({ isOpen }) => (isOpen ? '90deg' : '270deg')};
`;

const Drawer = ({
  setIsDrawerOpen,
  isDrawerOpen,
}: {
  isDrawerOpen: boolean;
  setIsDrawerOpen: any;
}) => {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [activeItem, setActiveItem] = useState(menuItems[0].index);
  const [activeSubItem, setActiveSubItem] = useState<number | null>();

  const handleMenuItemClick = (item: IMenuItem) => {
    setIsMenuOpen(false);
    setActiveSubItem(null);
    setActiveItem(item.index);
    // Add any logic you want to perform when a menu item is clicked
  };
  const handleSubMenuItemClick = (item: IMenuItem) => {
    setActiveSubItem(item.index);

    // Add any logic you want to perform when a sub menu item is clicked
  };
  const handleClickeableMenuItemClick = (item: IMenuItem) => {
    setIsMenuOpen(!isMenuOpen);
    setActiveItem(item.index);
    // Add any logic you want to perform when a menu item is clicked
  };

  return (
    <DrawerContainer $isDrawerOpen={isDrawerOpen}>
      <Button onClick={() => setIsDrawerOpen(false)}>Close</Button>
      <Title>Menu</Title>
      {menuItems.map((item, index) =>
        item.items ? (
          // Is a group menu item
          <MenuItemContainer key={`sub-menu-${index}-${item.index}`}>
            <GroupMenuItem
              $isActive={item.index === activeItem}
              onClick={() => handleClickeableMenuItemClick(item)}>
              {item.label}
              <Arrow isOpen={isMenuOpen && activeItem === item.index}>
                {'>'}
              </Arrow>
            </GroupMenuItem>
            {isMenuOpen &&
              activeItem === item.index &&
              item.items.map((item, subindex) => (
                <MenuItem
                  key={`menu--${item.index}`}
                  $isActive={index === activeItem && subindex === activeSubItem}
                  onClick={() => handleSubMenuItemClick(item)}>
                  {item.label}
                </MenuItem>
              ))}
          </MenuItemContainer>
        ) : (
          // Is a simple menu item
          <MenuItem
            key={`menu--${item.index}`}
            $isActive={item.index === activeItem}
            onClick={() => handleMenuItemClick(item)}>
            {item.label}
          </MenuItem>
        ),
      )}
    </DrawerContainer>
  );
};

export default Drawer;
