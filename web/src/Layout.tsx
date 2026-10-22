import { useState } from 'react'
import {
  AppstoreOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SettingOutlined,
  TeamOutlined,
} from '@ant-design/icons'
import { Button, Layout, Menu, Typography } from 'antd'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'

import { logout } from './api'

const MENU_ITEMS = [
  { key: '/users', icon: <TeamOutlined />, label: '用户管理' },
  { key: '/gates', icon: <AppstoreOutlined />, label: '网关设置' },
  { key: '/settings', icon: <SettingOutlined />, label: '系统设置' },
]

const TITLES: Record<string, string> = {
  '/users': '用户管理',
  '/gates': '网关设置',
  '/settings': '系统设置',
}

/** Rail, header and content frame shared by the three management pages. */
export default function AppLayout() {
  const [collapsed, setCollapsed] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()

  return (
    <Layout className="app-shell">
      <Layout.Sider
        className="app-sider"
        theme="light"
        width={216}
        collapsedWidth={88}
        collapsible
        collapsed={collapsed}
        trigger={null}
      >
        <div className="app-brand">{collapsed ? 'AD' : 'AuthDock'}</div>
        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          items={MENU_ITEMS}
          onClick={({ key }) => navigate(key)}
        />
      </Layout.Sider>

      <Layout>
        <Layout.Header className="app-header">
          <Button
            type="text"
            aria-label={collapsed ? '展开导航' : '折叠导航'}
            icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
            onClick={() => setCollapsed(!collapsed)}
          />
          <Typography.Title level={4} className="app-title">
            {TITLES[location.pathname] ?? '管理后台'}
          </Typography.Title>
          <Button type="text" danger icon={<LogoutOutlined />} onClick={() => logout()}>
            退出登录
          </Button>
        </Layout.Header>

        <Layout.Content className="app-content">
          <Outlet />
        </Layout.Content>
      </Layout>
    </Layout>
  )
}
