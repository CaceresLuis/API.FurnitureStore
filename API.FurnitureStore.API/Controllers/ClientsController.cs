using API.FurnitureStore.Data;
using Microsoft.AspNetCore.Mvc;
using API.FurnitureStore.Shared;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;

namespace API.FurnitureStore.API.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class ClientsController : ControllerBase
    {
        private readonly APIFurnitureContext _context;

        public ClientsController(APIFurnitureContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<IEnumerable<Client>> GetClients()
        {
            return await _context.Clients.ToListAsync();
        }

        [HttpGet("id")]
        public async Task<IActionResult> GetClient(int id)
        {
            Client client = await _context.Clients.FirstOrDefaultAsync(c => c.Id == id);

            if (client == null)
                return NotFound();

            return Ok(client);
        }

        [HttpPost]
        public async Task<IActionResult> CreateClient(Client client)
        {
            await _context.Clients.AddAsync(client);
            await _context.SaveChangesAsync();

            return CreatedAtAction("CreateClient", client.Id, client);
        }

        [HttpPut]
        public async Task<IActionResult> UpdateCliente(Client client)
        {
            _context.Clients.Update(client);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("id")]
        public async Task<IActionResult> DeleteCliente(int id)
        {
            Client? client = await _context.Clients.FindAsync(id);
            if (client == null)
                return NotFound();

            _context.Remove(client);
            await _context.SaveChangesAsync();
            return NoContent();
        }
    }
}
