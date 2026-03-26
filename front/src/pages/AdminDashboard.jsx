import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

//mission 4: composant pour le dashboard admin

function AdminDashboard() {
    const navigate = useNavigate();
    const user = JSON.parse(localStorage.getItem('user'));

    useEffect(() => {
        if (!user || user.role !== 'admin') {
            navigate('/dashboard');
        }
    }, [navigate, user]);

    return (
        <div>
            <h2> Bienvenue sur l espace administrateur </h2>
            <p> Bienvenue a l administrateur.</p>

            <button onClick={() => navigate('/dashboard')} style={{ marginLeft: '10px' }}>
                Retour au Dashboard
            </button>
        </div>

    );

}

export default AdminDashboard;