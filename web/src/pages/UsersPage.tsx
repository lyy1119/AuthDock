import { useCallback, useEffect, useState } from 'react'
import { CheckOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { App, Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import { createUser, deleteUser, listUsers, updateUser, type AdminUser, type Role } from '../api'

interface Draft {
  role: Role
  password: string
}

interface CreateValues {
  username: string
  password: string
  role: Role
}

const ROLE_OPTIONS: { value: Role; label: string }[] = [
  { value: 'user', label: '普通用户' },
  { value: 'admin', label: '管理员' },
]

/**
 * 用户管理: the table mirrors the sketch — username, an inline password field, a
 * role select, and a per-row confirm button plus delete. A password left empty
 * means "keep the current one".
 */
export default function UsersPage() {
  const { message } = App.useApp()
  const [users, setUsers] = useState<AdminUser[]>([])
  const [drafts, setDrafts] = useState<Record<number, Draft>>({})
  const [loading, setLoading] = useState(false)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form] = Form.useForm<CreateValues>()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const list = await listUsers()
      setUsers(list)
      setDrafts(
        Object.fromEntries(list.map((user) => [user.id, { role: user.role, password: '' }])) as Record<
          number,
          Draft
        >,
      )
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setLoading(false)
    }
  }, [message])

  useEffect(() => {
    void load()
  }, [load])

  const patchDraft = (id: number, patch: Partial<Draft>) => {
    setDrafts((current) => ({ ...current, [id]: { ...current[id], ...patch } }))
  }

  const save = async (user: AdminUser) => {
    const draft = drafts[user.id]
    if (!draft) return
    setBusyId(user.id)
    try {
      const result = await updateUser(user.id, {
        role: draft.role,
        ...(draft.password ? { password: draft.password } : {}),
      })
      if (result.logged_out) {
        void message.warning('已取消自己的管理员身份，请重新登录')
        window.location.href = new URL('../login', window.location.href).href
        return
      }
      void message.success(`已保存 ${user.username}`)
      await load()
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (user: AdminUser) => {
    setBusyId(user.id)
    try {
      await deleteUser(user.id)
      void message.success(`已删除 ${user.username}`)
      await load()
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setBusyId(null)
    }
  }

  const create = async (values: CreateValues) => {
    setCreating(true)
    try {
      await createUser(values)
      setCreateOpen(false)
      form.resetFields()
      void message.success(`已创建 ${values.username}`)
      await load()
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setCreating(false)
    }
  }

  const columns: ColumnsType<AdminUser> = [
    {
      title: '用户名',
      dataIndex: 'username',
      render: (_value, user) => (
        <Space size={8}>
          <Typography.Text strong>{user.username}</Typography.Text>
          {user.self ? <Tag color="blue">当前账号</Tag> : null}
        </Space>
      ),
    },
    {
      title: '密码',
      key: 'password',
      width: 260,
      render: (_value, user) => (
        <Input.Password
          placeholder="留空则不修改"
          autoComplete="new-password"
          value={drafts[user.id]?.password ?? ''}
          onChange={(event) => patchDraft(user.id, { password: event.target.value })}
        />
      ),
    },
    {
      title: '身份',
      key: 'role',
      width: 170,
      render: (_value, user) => (
        <Select
          style={{ width: '100%' }}
          value={drafts[user.id]?.role ?? user.role}
          options={ROLE_OPTIONS}
          onChange={(role: Role) => patchDraft(user.id, { role })}
        />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 200,
      align: 'right',
      render: (_value, user) => (
        <Space>
          <Button
            type="primary"
            size="small"
            icon={<CheckOutlined />}
            loading={busyId === user.id}
            onClick={() => void save(user)}
          >
            保存
          </Button>
          <Popconfirm
            title={`删除用户 ${user.username}？`}
            description="删除后该账号不能再登录。"
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            disabled={user.self}
            onConfirm={() => void remove(user)}
          >
            <Button
              danger
              size="small"
              icon={<DeleteOutlined />}
              disabled={user.self}
              title={user.self ? '不能删除当前登录的账号' : '删除该账号'}
            />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div className="page">
      <div className="page-toolbar">
        <Typography.Text type="secondary">
          修改身份或填写新密码后，点该行的“保存”生效；密码留空表示保持原密码。
        </Typography.Text>
        <span className="grow" />
        <Button
          type="primary"
          icon={<PlusOutlined />}
          onClick={() => {
            form.resetFields()
            setCreateOpen(true)
          }}
        >
          新增用户
        </Button>
      </div>

      <Table
        rowKey="id"
        columns={columns}
        dataSource={users}
        loading={loading}
        pagination={false}
        scroll={{ x: 880 }}
      />

      <Modal
        title="新增用户"
        open={createOpen}
        okText="创建"
        cancelText="取消"
        confirmLoading={creating}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
      >
        <Form form={form} layout="vertical" initialValues={{ role: 'user' }} onFinish={create}>
          <Form.Item
            name="username"
            label="用户名"
            rules={[
              { required: true, message: '请输入用户名' },
              { max: 20, message: '用户名最多 20 个字符' },
              { pattern: /^[A-Za-z0-9._-]+$/, message: '只能包含字母、数字、下划线、连字符和点' },
            ]}
          >
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="password"
            label="密码"
            rules={[
              { required: true, message: '请输入密码' },
              { min: 8, message: '密码至少 8 个字符' },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item name="role" label="身份">
            <Select options={ROLE_OPTIONS} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
