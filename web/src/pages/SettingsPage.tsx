import { useCallback, useEffect, useState } from 'react'
import { Alert, App, Button, Form, Input, Radio, Space, Switch, Typography } from 'antd'

import { getSettings, saveSettings, type Settings } from '../api'

interface SettingsValues {
  gateway_domain: string
  upstream_host: 'preserve' | 'upstream'
  upstream_insecure: boolean
}

const EMPTY: SettingsValues = {
  gateway_domain: '',
  upstream_host: 'preserve',
  upstream_insecure: false,
}

/**
 * 系统设置: the gateway base domain plus the two knobs that decide how the
 * gateway talks to published services.
 */
export default function SettingsPage() {
  const { message } = App.useApp()
  const [loaded, setLoaded] = useState<SettingsValues>(EMPTY)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [form] = Form.useForm<SettingsValues>()

  const apply = useCallback(
    (settings: Settings) => {
      const values: SettingsValues = {
        gateway_domain: settings.gateway_domain,
        upstream_host: settings.upstream_host,
        upstream_insecure: settings.upstream_insecure,
      }
      setLoaded(values)
      form.setFieldsValue(values)
    },
    [form],
  )

  const load = useCallback(async () => {
    setLoading(true)
    try {
      apply(await getSettings())
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setLoading(false)
    }
  }, [apply, message])

  useEffect(() => {
    void load()
  }, [load])

  const save = async (values: SettingsValues) => {
    setSaving(true)
    try {
      apply(await saveSettings({ ...values, gateway_domain: values.gateway_domain.trim() }))
      void message.success('已保存')
    } catch (error) {
      void message.error((error as Error).message)
    } finally {
      setSaving(false)
    }
  }

  const insecure = Form.useWatch('upstream_insecure', form)

  return (
    <div className="page">
      <Typography.Text type="secondary">
        网关域名是这类地址的公共后缀：<code>&lt;子域名&gt;.&lt;网关域名&gt;/&lt;路径前缀&gt;</code>。
      </Typography.Text>

      <Form form={form} layout="vertical" style={{ maxWidth: 640 }} initialValues={EMPTY} onFinish={save}>
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
          <Input placeholder="gw.example.net" autoComplete="off" allowClear />
        </Form.Item>

        <Form.Item
          name="upstream_host"
          label="上游 Host 传递方式"
          extra="上游如果是另一个 Caddy / nginx（按域名分站点），请选“保留原始 Host”。"
        >
          <Radio.Group>
            <Space direction="vertical">
              <Radio value="preserve">保留原始 Host（推荐）</Radio>
              <Radio value="upstream">使用上游地址作为 Host</Radio>
            </Space>
          </Radio.Group>
        </Form.Item>

        <Form.Item
          name="upstream_insecure"
          label="跳过上游 HTTPS 证书校验"
          valuePropName="checked"
          extra="仅当上游使用自签证书或内部 CA（例如 Caddy 的 tls internal）时开启；开启后网关不再校验上游证书。"
        >
          <Switch checkedChildren="跳过" unCheckedChildren="校验" />
        </Form.Item>

        <Form.Item>
          <Space>
            <Button onClick={() => form.setFieldsValue(loaded)} disabled={loading || saving}>
              取消
            </Button>
            <Button type="primary" htmlType="submit" loading={saving}>
              保存
            </Button>
          </Space>
        </Form.Item>
      </Form>

      {insecure ? (
        <Alert
          type="warning"
          showIcon
          message="已跳过上游 HTTPS 证书校验"
          description="这会让网关接受任何证书，请只在你信任的内部网络里使用。"
        />
      ) : null}

      <Typography.Text type="secondary" className="cell-hint">
        网关域名留空表示不启用；已配置的网关规则不会被删除。
      </Typography.Text>
    </div>
  )
}
