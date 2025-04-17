import { useEffect, useState } from 'react'
import axios from 'axios'
import { ArrowPathIcon, KeyIcon } from '@heroicons/react/24/outline'

interface UserInfo {
  sub: string
  email?: string
  email_verified?: boolean
  preferred_username?: string
  [key: string]: any
}

export default function TestPage() {
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [apiKeyLoading, setApiKeyLoading] = useState(false)

  const fetchUserInfo = async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await axios.get('/oauth/userinfo')
      setUserInfo(response.data)
      setLastUpdated(new Date())
    } catch (err) {
      setError('Failed to fetch user information')
      console.error('Error fetching user info:', err)
    } finally {
      setLoading(false)
    }
  }

  const downloadApiKey = async () => {
    setApiKeyLoading(true)
    setError(null)
    try {
      // const response = await axios.get('/oauth/apikey')
      // const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
      // const url = window.URL.createObjectURL(blob)
      const url = '/oauth/apikey'

      const a = document.createElement('a')
      a.href = url
      a.target = '_blank'
      a.rel = 'noopener noreferrer'
      // a.download = 'api-key.json'
      document.body.appendChild(a)
      a.click()
      // window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      setError('Failed to download API key')
      console.error('Error downloading API key:', err)
    } finally {
      setApiKeyLoading(false)
    }
  }

  // Format the field name for display
  const formatFieldName = (name: string) => {
    return name
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ')
  }

  // Format the field value for display
  const formatFieldValue = (value: any) => {
    if (typeof value === 'boolean') {
      return value ? 'Yes' : 'No'
    }
    return String(value)
  }

  return (
    <div className="space-y-6">
      <div className="bg-white shadow rounded-lg overflow-hidden">
        <div className="px-6 py-5 border-b border-gray-200 flex justify-between items-center">
          <div>
            <h2 className="text-xl font-semibold text-gray-900">User Information</h2>
            {lastUpdated && (
              <p className="mt-1 text-sm text-gray-500">
                Last updated: {lastUpdated.toLocaleTimeString()}
              </p>
            )}
          </div>
          <div className="flex space-x-3">
            <button
              onClick={downloadApiKey}
              disabled={apiKeyLoading}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 disabled:opacity-50 transition-colors duration-150"
            >
              {apiKeyLoading ? (
                <>
                  <ArrowPathIcon className="animate-spin -ml-1 mr-2 h-4 w-4" />
                  Loading...
                </>
              ) : (
                <>
                  <KeyIcon className="-ml-1 mr-2 h-4 w-4" />
                  Download API Key
                </>
              )}
            </button>
            <button
              onClick={fetchUserInfo}
              disabled={loading}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 transition-colors duration-150"
            >
              {loading ? (
                <>
                  <ArrowPathIcon className="animate-spin -ml-1 mr-2 h-4 w-4" />
                  Loading...
                </>
              ) : (
                <>
                  <ArrowPathIcon className="-ml-1 mr-2 h-4 w-4" />
                  Test API
                </>
              )}
            </button>
          </div>
        </div>

        <div className="px-6 py-5">
          {error ? (
            <div className="bg-red-50 border border-red-200 rounded-md p-4">
              <div className="flex">
                <div className="flex-shrink-0">
                  <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                  </svg>
                </div>
                <div className="ml-3">
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          ) : userInfo ? (
            <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
              {Object.entries(userInfo).map(([key, value]) => (
                <div key={key} className="sm:col-span-1">
                  <dt className="text-sm font-medium text-gray-500">{formatFieldName(key)}</dt>
                  <dd className="mt-1 text-sm text-gray-900 break-all">{formatFieldValue(value)}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <div className="text-center py-6 text-gray-500">
              Click the "Test API" button to fetch user information
            </div>
          )}
        </div>
      </div>
    </div>
  )
} 