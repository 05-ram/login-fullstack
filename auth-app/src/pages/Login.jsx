import React, { useState } from 'react'
import Button from 'react-bootstrap/esm/Button';
import { useNavigate } from 'react-router-dom';
import Form from 'react-bootstrap/Form';
import axios from 'axios';

const Login = () => {
    const navigate = useNavigate();
    const [values, setValues] = useState(
        {
            email: '',
            password: ''
        }
    )
    axios.defaults.withCredentials = true;
    const handleSubmit = (event) => {
        event.preventDefault();
        axios.post('http://localhost:8082/login', values)
            .then(res => {
                if (res.data.Status === 'Success') {
                    navigate('/')
                }
                else {
                    alert(res.data.Error)
                }
            })
            .catch(err => console.log(err));
    }
    return (
        <div className="d-flex flex-column justify-content-center align-items-center vh-100">
            <h1>Login</h1>
            <div className='bg-dark text-white rounded w-25 p-5'>
                <Form onSubmit={handleSubmit}>
                    <Form.Group className="mb-4">
                        <Form.Label>Email address</Form.Label>
                        <Form.Control type="email" placeholder="enter your email" className='rounded-0' name='email' onChange={(e) => setValues({ ...values, email: e.target.value })} />
                    </Form.Group> <Form.Group className="mb-4">
                        <Form.Label>Password</Form.Label>
                        <Form.Control type="password" placeholder="enter your password" className='rounded-0' name='password' onChange={(e) => setValues({ ...values, password: e.target.value })} />
                    </Form.Group>
                    <Button variant='success' type='submit' className='mt-2 w-100'>Login</Button>
                    <Button variant="outline-light" onClick={() => navigate('/register')} className='mt-3 w-100'>Create an Account</Button>
                </Form>
            </div>
        </div >
    )
}

export default Login;