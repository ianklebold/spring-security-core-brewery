# SPIRNG SECURITY

## DEFAULT HTTP BASIC AUTH

Lo activamos con solo añadir la siguiente dependencia

```
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
```

Nos genera al levantar el server, que es la password. El username es user

Si utilizamos la api sin autenticacion obtendremos un 401, no autorizado. 
![image](https://user-images.githubusercontent.com/56406481/211181840-56326d45-d41c-462a-98ea-ed4fd10c6e45.png)

El http basic lo que hace es, en la mismo header de la request, adjuntar el user y el password codificados en Base64.

Por ejemplo

```
user:08446db7-9abe-475f-b4d9-f24293380d34
Codificado seria:
dXNlcjowODQ0NmRiNy05YWJlLTQ3NWYtYjRkOS1mMjQyOTMzODBkMzQ=
```

![image](https://user-images.githubusercontent.com/56406481/211182030-e7a8adb6-68a9-45a7-b7e0-2983116a4449.png)

Es importante entender una cosa, con postman siempre que queremos consultar debemos setear la autenticacion, en cambio con un navegador este puede mantener nuestra autenticacion en una cookie hasta que deseemos finalizar la sesion. 

En el propio header, incluso en la cookie se podra ver la clave. Eso hace que este metodo de autenticacion sea bastante debil. Las credenciales se pasan al servidor desencriptadas y estas pueden ser leidas en el trafico de red, es por ello que debemos usar HTTPS.

La configuracion preparada para esto es:

```
    protected void configure(HttpSecurity http) throws Exception {
        this.logger.debug("Using default configure(HttpSecurity). If subclassed this will potentially override subclass configure(HttpSecurity).");
        ((HttpSecurity)((HttpSecurity)    ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)
        http.authorizeRequests()
              .anyRequest())
              .authenticated()
              .and())
              .formLogin()
              .and())
            .httpBasic();
    }
```

### Customized username and password

En tu application.properties seteamos las variables de la siguiente manera

```
spring.security.user.name=ian
spring.security.user.password=jedi
```

Esto lo que hace es sobreescribir los valores que antes teniamos. Hacerlo en el properties es una buena idea si consideramos un deploy de nuestra aplicacion.
En consola ya no obtenemos la pass para la autenticacion, lo cual es correcto porque ya la sobreescribimos. 

```
ian:jedi
Codificado seria:
aWFuOmplZGk=
```

![image](https://user-images.githubusercontent.com/56406481/211182368-a77db3b0-4e32-4740-be77-6f667605b3a1.png)


## Spring security filter chain

En la siguiente imagen vemos como el servlet "Dispatcher servlet" de spring funciona. Por default pasa por varias capas de filtros, para luego llegar a este servlet que es el que redirecciona (Dependiendo de la uri) a un controlador y luego a una vista.


![image](https://user-images.githubusercontent.com/56406481/211183016-85a6cfb3-f665-4cbd-9f4d-8e55719802ed.png)

Spring mejora esto, anadiendo un filtro de autenticacion, en donde a un filtro lo convierte en un Bean filter, este bean nos permite configurarlo de la menra que nostros necesitemos, por ejemplo dependiendo de la direccion que se desee se puede recurrir a una serie de filtros. Una vez se pasa ese bean filter se retoma el camino del FilterChain por default.

![image](https://user-images.githubusercontent.com/56406481/211183118-cbc8abf1-660f-4a02-8b22-2b4e6e5c494e.png)


## JAVA CONFIGURATION

Para ello debemos crear una carpeta config y dentro crear una clase SecurityConfig.java. Aqui pondremos la logica que gestionara la seguridad de spring.

###  PERMIT ALL WITH URL

Es una configuracion que permite hacer cualquier tipo de request (GET, POST, PUT, ETC) y con permitALL estamos permitiendo que cualquiera pueda hacerlo en los endpoints que indiquemos

```
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        ((HttpSecurity)((HttpSecurity) ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)
                http
                        .authorizeRequests(authorize -> 
                                authorize
                                        .antMatchers("/","webjars/**","/login","/resources/**")
                                        .permitAll()
                        )
                        .authorizeRequests()
                            .anyRequest()) //Cualquier request debe estar autenticado
                            .authenticated()
                        .and())
                        .formLogin()
                        .and())
                    .httpBasic();
    }

}
```
Cual es la diferencia entre : 

"/api/v1/user/*" y "/api/v1/user/**" 

"/api/v1/user/*" - Permite agregar un valor mas incluyendo hasta otro /, despues del comienzo 

"/api/v1/user/**" - Permite agregar mas de un valor , inclyendo otro / 

** los ** son wildcards **

Aqui estamos permitiendo el endpoint de /beers/find y el de la busqueda de una cerveza especifica beers?, el * permite agregar cualquier otro valor

```
.antMatchers("/beers/find","/beers*").permitAll()

Notemos lo siguiente que la segunda expresion ya esta aceptando a la primera, por lo tanto solo nos quedamos con la segunda. 

.antMatchers("/beers*").permitAll()
```

###  PERMIT ALL WITH URL AND HTTP METHOD

Ahora podemos indicaque no queremos que todas las operaciones HTTP sean realizadas por todos, sino que seleccionaremos cual. En este caso solo GET

```
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        ((HttpSecurity)((HttpSecurity) ((ExpressionUrlAuthorizationConfigurer.AuthorizedUrl)
                http
                        .authorizeRequests(authorize ->
                                authorize
                                        .antMatchers("/","webjars/**","/login","/resources/**")
                                        .permitAll()
                                        .antMatchers("/beers*").permitAll()
                                        .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                        )
                        .authorizeRequests()
                            .anyRequest()) //Cualquier request debe estar autenticado
                            .authenticated()
                        .and())
                        .formLogin()
                        .and())
                    .httpBasic();
    }
```

.antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll() 

GET es una operacion segura, por lo tanto no importa si usamos doble *


###  MVC PATCH Matchers

En lugar de usar wildcards podemos usar simplemente MVCMATCHERS, el cual nos permite utilizar los mismos endpoints que tenemos en los controllers

por ejemplo:


```
.mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll()
```

Si usabamos antMatches tendriamos que usar los wildcards *

## IN MEMORY AUTHENTICATION PROVIDER





