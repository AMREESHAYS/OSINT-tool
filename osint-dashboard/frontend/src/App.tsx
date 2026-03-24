import { Navigate, Route, Routes } from 'react-router-dom';

import InputPage from './pages/InputPage';
import ResultsPage from './pages/ResultsPage';

function App() {
  return (
    <Routes>
      <Route path="/" element={<InputPage />} />
      <Route path="/results/:id" element={<ResultsPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
