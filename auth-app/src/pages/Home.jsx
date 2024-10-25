import axios from 'axios';
import React, { useEffect, useState } from 'react';
import Button from 'react-bootstrap/esm/Button';
import { useNavigate } from 'react-router-dom';

const Home = () => {
    const [auth, setAuth] = useState(false);
    const [message, setMessage] = useState('');
    const [name, setName] = useState('');

    const navigate = useNavigate();


    axios.defaults.withCredentials = true;

    useEffect(() => {
        axios.get('http://localhost:8082')
            .then(res => {
                if (res.data.Status === 'Success') {
                    setAuth(true);
                    setName(res.data.name)
                }
                else {
                    setAuth(false);
                    setMessage(res.data.Error)
                }
            })
    }, [])

    const handleDelete = () => {
        axios.get('http://localhost:8082/logout')
            .then(res => {
                navigate('/login')
                alert('logged Out')
            })
            .catch(err => console.log(err))
    }
    return (
        <div className='container'>
            {
                auth ?
                    <div>
                        <h3>You are Authorized {name}</h3>
                        <Button variant="danger" onClick={handleDelete}>Log Out</Button>
                    </div>
                    :
                    <div>
                        <h3>{message}</h3>
                        <Button onClick={() => navigate('/login')}>Login</Button>
                    </div>
            }
        </div>
    )
}

export default Home; 