import ErrorPage from "../pages/ErrorPage";
import Home from "../pages/Home";
import { createBrowserRouter } from 'react-router-dom';
import Register from "../pages/Register";
import Login from "../pages/Login";

const RouterData = () => {
    const strictRoute = createBrowserRouter(
        [
            {
                path: '/',
                element: <Home />,
                errorElement: <ErrorPage />
            },
            {
                path: '/register',
                element: <Register />,
            },
            {
                path: '/login',
                element: <Login />,
            }
        ]
    )
    return strictRoute;
}

export default RouterData;