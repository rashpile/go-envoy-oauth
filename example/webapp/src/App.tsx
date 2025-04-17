import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import TestPage from './pages/TestPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<TestPage />} />
      </Route>
    </Routes>
  )
}

export default App 