function acm_NextId(tableName, callback) {
//  fetch( 'http://localhost:54032/api2/nextid', {                                      //#.(51013.01.37)         
//  fetch(`${window.FVARS.AUTH_API_URL}/nextid`, {                                      //#.(51013.01.37)        
    fetch(`${window.FVARS.SERVER_API_URL}/nextid`, {                                    // .(51013.01.37)        
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ tableName: tableName })
    })
        .then(response => response.json())
        .then(data => callback(data.nextId || 1))
        .catch(() => callback(1));
}