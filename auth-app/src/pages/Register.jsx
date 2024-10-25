import React, { useState } from 'react';
import Form from 'react-bootstrap/Form';
import Button from 'react-bootstrap/Button';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const Register = () => {
    const [values, setValues] = useState(
        {
            name: '',
            email: '',
            password: ''
        }
    )
    const navigate = useNavigate();
    const handleSubmit = (event) => {
        event.preventDefault();
        axios.post('http://localhost:8082/register', values)
            .then(res => {
                if (res.data.Status === 'Success') {
                    navigate('/login')
                }
                else {
                    alert('Error')
                }
            })
            .catch(err => console.log(err));
    }
    return (
        <div className="d-flex flex-column justify-content-center align-items-center vh-100">
            <h1>Register</h1>
            <div className='bg-dark text-white rounded w-25 p-5'>
                <Form onSubmit={handleSubmit}>
                    <Form.Group className="mb-4">
                        <Form.Label>User Name</Form.Label>
                        <Form.Control type="text" placeholder="enter your name" name='name' className='rounded-0' onChange={(e) => setValues({ ...values, name: e.target.value })} />
                    </Form.Group>
                    <Form.Group className="mb-4">
                        <Form.Label>Email address</Form.Label>
                        <Form.Control type="email" placeholder="enter your email" className='rounded-0' name='email' onChange={(e) => setValues({ ...values, email: e.target.value })} />
                    </Form.Group>
                    <Form.Group className="mb-4">
                        <Form.Label>Password</Form.Label>
                        <Form.Control type="password" placeholder="enter your password" className='rounded-0' name='password' onChange={(e) => setValues({ ...values, password: e.target.value })} />
                    </Form.Group>
                    <Button variant='success' type='submit' className='mt-2 w-100'>Register</Button>
                    <Button variant="outline-light" onClick={() => navigate('/login')} className='mt-3 w-100'>Login</Button>
                </Form>
            </div>
        </div >
    )
}

export default Register