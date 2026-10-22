import { useCallback, useEffect, useState } from 'react'
import { CheckOutlined, DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import { Alert, App, Button, Form, Input, Modal, Popconfirm, Select, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'

import {
  createGate,
  deleteGate,
  listGates,
  listUsers,
  updateGate,
  type AdminUser,
  type Gate,
  type GateInput,
} from '../api'

interface Draft {
  name: string
  from: string
  to_prefix: string
  to_suffix: string
  user_id: number | null
}

const EMPTY_DRAFT: Draft = { name: '', from: '', to_prefix: '', to_suffix: '', user_id: null }

/** The scope select uses 0 for "global" because Select values must be unique. */
const GLOBAL = 0

/**
 * 网关设置: one row per gate. 目标 is the public side
 * `<to_prefix>.<gateway domain>/<to_suffix><api 转发内容>`, 源 is the upstream
 * address the gateway forwards to (`from`).
 */
export default function GatesPage() {
  const { message } = App.useApp()
  const [domain, setDomain] = useState('')
  const [users, setUsers] = useState<AdminUser[]>([])
  const [gates, setGates] = useState<Gate[]>([])
  const [drafts, setDrafts] = useState<Record<number, Draft>>({})
  const [loading, setLoading] = useState(false)
  const [busyId, setBusyId] = useState<number | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form] = Form.useForm<GateInput>()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const [data, accounts] = await Promise.all([listGates(), listUsers()])
      setDomain(data.gatewayDomain)
      setUsers(accounts)
      setGates(data.gates)
      setDrafts(
        Object.fromEntries(
          data.gates.map((gate) => [
            gate.id,
            {
              name: gate.name,
              from: gate.from,
              to_prefix: gate.to_prefix,
              to_suffix: gate.to_suffix,
              user_id: gate.user_id,
            },
          ]),
        ) as Record<number, Draft>,
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

  const save = async (gate: Gate) => {
    const draft = drafts[gate.id]
    if (!draft) return
    setBusyId(gate.id)
    try {
      await updateGate(gate.id, draft)
      void message.success(`已保存网关「${draft.name}」`)
      await load()
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setBusyId(null)
    }
  }

  const remove = async (gate: Gate) => {
    setBusyId(gate.id)
    try {
      await deleteGate(gate.id)
      void message.success(`已删除网关「${gate.name}」`)
      await load()
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setBusyId(null)
    }
  }

  const create = async (values: GateInput) => {
    setCreating(true)
    try {
      await createGate({
        ...values,
        to_suffix: values.to_suffix ?? '',
        user_id: values.user_id === GLOBAL || values.user_id === undefined ? null : values.user_id,
      })
      setCreateOpen(false)
      form.resetFields()
      void message.success(`已添加网关「${values.name}」`)
      await load()
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setCreating(false)
    }
  }

  const columns: ColumnsType<Gate> = [
    {
      title: '名称',
      key: 'name',
      width: 200,
      render: (_value, gate) => (
        <Input
          value={drafts[gate.id]?.name ?? gate.name}
          onChange={(event) => patchDraft(gate.id, { name: event.target.value })}
        />
      ),
    },
    {
      title: '目标',
      key: 'target',
      render: (_value, gate) => {
        const draft = drafts[gate.id] ?? EMPTY_DRAFT
        return (
          <Space direction="vertical" size={2} style={{ width: '100%' }}>
            <Space size={4} className="gate-target" wrap>
              <span className="literal">https://</span>
              <Input
                style={{ width: 132 }}
                value={draft.to_prefix}
                onChange={(event) => patchDraft(gate.id, { to_prefix: event.target.value })}
                aria-label="目标子域名"
              />
              <span className="literal">.{domain || '网关域名未设置'}/</span>
              <Input
                style={{ width: 128 }}
                placeholder="可留空"
                value={draft.to_suffix}
                onChange={(event) => patchDraft(gate.id, { to_suffix: event.target.value })}
                aria-label="目标路径前缀"
              />
            </Space>
            <Typography.Text type="secondary" className="cell-hint">
              转发内容会接在路径前缀之后
            </Typography.Text>
          </Space>
        )
      },
    },
    {
      title: '源',
      key: 'from',
      width: 230,
      render: (_value, gate) => (
        <Input
          placeholder="10.0.0.1:1234"
          value={drafts[gate.id]?.from ?? gate.from}
          onChange={(event) => patchDraft(gate.id, { from: event.target.value })}
          aria-label="源地址"
        />
      ),
    },
    {
      title: '作用域',
      key: 'scope',
      width: 190,
      render: (_value, gate) => {
        const current = drafts[gate.id]?.user_id ?? null
        return (
          <Select
            style={{ width: '100%' }}
            value={current === null ? GLOBAL : current}
            onChange={(value: number) => patchDraft(gate.id, { user_id: value === GLOBAL ? null : value })}
            options={[
              { value: GLOBAL, label: '全局（所有账号）' },
              ...users.map((user) => ({ value: user.id, label: user.username })),
            ]}
            aria-label="作用域"
          />
        )
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 180,
      align: 'right',
      render: (_value, gate) => (
        <Space>
          <Button
            type="primary"
            size="small"
            icon={<CheckOutlined />}
            loading={busyId === gate.id}
            onClick={() => void save(gate)}
          >
            保存
          </Button>
          <Popconfirm
            title={`删除网关「${gate.name}」？`}
            okText="删除"
            cancelText="取消"
            okButtonProps={{ danger: true }}
            onConfirm={() => void remove(gate)}
          >
            <Button danger size="small" icon={<DeleteOutlined />} aria-label="删除该网关" />
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div className="page">
      {domain ? null : (
        <Alert
          type="warning"
          showIcon
          message="还没有设置网关域名"
          description="网关域名在「系统设置」里配置，例如 gw.example.net。设置后这里的每条网关才会生成可访问的地址。"
        />
      )}

      <div className="page-toolbar">
        <Typography.Text type="secondary">
          网关把 <code>https://&lt;子域名&gt;.{domain || '网关域名'}/&lt;路径前缀&gt;</code> 的请求转发到源地址。
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
          新增网关
        </Button>
      </div>

      <Table
        rowKey="id"
        columns={columns}
        dataSource={gates}
        loading={loading}
        pagination={false}
        scroll={{ x: 1080 }}
        locale={{ emptyText: '还没有网关，点右上角「新增网关」添加一个' }}
      />

      <Modal
        title="新增网关"
        open={createOpen}
        okText="添加"
        cancelText="取消"
        confirmLoading={creating}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        width={520}
      >
        <Form
          form={form}
          layout="vertical"
          initialValues={{ to_suffix: '' }}
          onFinish={create}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[
              { required: true, message: '请输入名称' },
              { max: 50, message: '名称最多 50 个字符' },
            ]}
          >
            <Input placeholder="例如：日历" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="to_prefix"
            label="目标子域名"
            extra={`完整地址：https://<子域名>.${domain || '网关域名'}/<路径前缀>`}
            rules={[
              { required: true, message: '请输入子域名' },
              {
                pattern: /^(\*|[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)$/,
                message: '只能是字母、数字、连字符，或使用 * 通配',
              },
            ]}
          >
            <Input placeholder="calendar" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="to_suffix"
            label="目标路径前缀"
            extra="可留空；填写时会插在转发内容前面，例如 app/"
            rules={[{ max: 255, message: '最多 255 个字符' }, { pattern: /^\S*$/, message: '不能包含空格' }]}
          >
            <Input placeholder="留空表示整个子域名" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="user_id"
            label="作用域"
            extra="全局表示所有账号都能使用；选择某个账号后只有该账号可用"
            initialValue={GLOBAL}
          >
            <Select
              options={[
                { value: GLOBAL, label: '全局（所有账号）' },
                ...users.map((user) => ({ value: user.id, label: user.username })),
              ]}
            />
          </Form.Item>
          <Form.Item
            name="from"
            label="源地址"
            extra="网关转发到的上游，例如 10.0.0.1:1234 或 http://10.0.0.1:1234"
            rules={[
              { required: true, message: '请输入源地址' },
              { pattern: /^\S+$/, message: '不能包含空格' },
            ]}
          >
            <Input placeholder="10.0.0.1:1234" autoComplete="off" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}
