import { useCallback, useEffect, useState } from 'react'
import { App, Button, Form, Input, Space, Typography } from 'antd'

import { getSettings, saveSettings } from '../api'

interface SettingsValues {
  gateway_domain: string
}

/**
 * 系统设置: the gateway base domain that the 网关设置 page appends subdomains to.
 */
export default function SettingsPage() {
  const { message } = App.useApp()
  const [loaded, setLoaded] = useState('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm<SettingsValues>()

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const settings = await getSettings()
      setLoaded(settings.gateway_domain)
      form.setFieldsValue({ gateway_domain: settings.gateway_domain })
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setLoading(false)
    }
  }, [form, message])

  useEffect(() => {
    void load()
  }, [load])

  const save = async (values: SettingsValues) => {
    setSaving(true)
    try {
      const settings = await saveSettings({ gateway_domain: values.gateway_domain.trim() })
      setLoaded(settings.gateway_domain)
      form.setFieldsValue({ gateway_domain: settings.gateway_domain })
      void message.success('已保存')
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="page">
      <Typography.Text type="secondary">
        网关域名是这类地址的公共后缀：<code>&lt;子域名&gt;.&lt;网关域名&gt;/&lt;路径前缀&gt;</code>。
      </Typography.Text>

      <Form
        form={form}
        layout="inline"
        style={{ maxWidth: 640 }}
        initialValues={{ gateway_domain: '' }}
        onFinish={save}
      >
        <Form.Item
          name="gateway_domain"
          label="网关域名"
          rules={[
            {
              pattern: /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$/,
              message: '请输入裸域名，例如 gw.example.net（不要带 http:// 或路径）',
            },
          ]}
        >
          <Input placeholder="gw.example.net" autoComplete="off" style={{ width: 280 }} allowClear />
        </Form.Item>
        <Form.Item>
          <Space>
            <Button
              onClick={() => form.setFieldsValue({ gateway_domain: loaded })}
              disabled={loading || saving}
            >
              取消
            </Button>
            <Button type="primary" htmlType="submit" loading={saving}>
              保存
            </Button>
          </Space>
        </Form.Item>
      </Form>

      <Typography.Text type="secondary" className="cell-hint">
        留空表示不启用网关地址显示；已配置的网关规则不会被删除。
      </Typography.Text>
    </div>
  )
}
